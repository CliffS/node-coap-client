import * as crypto from "crypto";
import * as dgram from "dgram";
import { EventEmitter } from "events";
import { dtls } from "node-dtls-client";
import * as nodeUrl from "url";
import { ContentFormats } from "./ContentFormats";
import { createDeferredPromise, DeferredPromise } from "./lib/DeferredPromise";
import { Origin } from "./lib/Origin";
import { SocketWrapper } from "./lib/SocketWrapper";
import { Message, MessageCode, MessageCodes, MessageType } from "./Message";
import { BinaryOption, NumericOption, Option, Options, StringOption } from "./Option";

// initialize debugging
import * as debugPackage from "debug";
const debug = debugPackage("node-coap-client");

// print version info
// tslint:disable-next-line:no-var-requires
const npmVersion = require("../package.json").version;
debug(`CoAP client version ${npmVersion}`);

export type RequestMethod = "get" | "post" | "put" | "delete";

/** Options to control CoAP requests */
export interface RequestOptions {
	/** Whether to keep the socket connection alive. Speeds up subsequent requests */
	keepAlive?: boolean;
	/** Whether we expect a confirmation of the request */
	confirmable?: boolean;
	/** Whether this message will be retransmitted on loss */
	retransmit?: boolean;
}

export interface CoapResponse {
	code: MessageCode;
	format: ContentFormats;
	payload?: Buffer;
}

function urlToString(url: nodeUrl.Url): string {
	return `${url.protocol}//${url.hostname}:${url.port}${url.pathname}`;
}

interface ConnectionInfo {
	origin: Origin;
	socket: SocketWrapper;
	lastToken: Buffer;
	lastMsgId: number;
}

interface IPendingRequest {
	connection: ConnectionInfo;
	url: string;
	originalMessage: Message; // allows resending the message, includes token and message id
	retransmit: RetransmissionInfo;
	// either (request):
	promise: Promise<CoapResponse>;
	// or (observe)
	callback: (resp: CoapResponse) => void;
	keepAlive: boolean;
	observe: boolean;
	concurrency: number;
}
class PendingRequest extends EventEmitter implements IPendingRequest {

	constructor(initial?: IPendingRequest) {
		super();
		if (!initial) return;

		this.connection = initial.connection;
		this.url = initial.url;
		this.originalMessage = initial.originalMessage;
		this.retransmit = initial.retransmit;
		this.promise = initial.promise;
		this.callback = initial.callback;
		this.keepAlive = initial.keepAlive;
		this.observe = initial.observe;
		this._concurrency = initial.concurrency;
	}

	public connection: ConnectionInfo;
	public url: string;
	public originalMessage: Message; // allows resending the message, includes token and message id
	public retransmit: RetransmissionInfo;
	// either (request):
	public promise: Promise<CoapResponse>;
	// or (observe)
	public callback: (resp: CoapResponse) => void;
	public keepAlive: boolean;
	public observe: boolean;

	private _concurrency: number;
	public set concurrency(value: number) {
		const changed = value !== this._concurrency;
		this._concurrency = value;
		if (changed) this.emit("concurrencyChanged", this);
	}
	public get concurrency(): number {
		return this._concurrency;
	}

	public queueForRetransmission(): void {
		if (this.retransmit != null && typeof this.retransmit.action === "function") {
			this.retransmit.jsTimeout = setTimeout(this.retransmit.action, this.retransmit.timeout);
		}
	}
}

interface QueuedMessage {
	connection: ConnectionInfo;
	message: Message;
}

export interface SecurityParameters {
	psk: { [identity: string]: string };
	// TODO support more
}

interface RetransmissionInfo {
	jsTimeout: any;
	action: () => void;
	timeout: number;
	counter: number;
}
// TODO: make configurable
const RETRANSMISSION_PARAMS = {
	ackTimeout: 2,
	ackRandomFactor: 1.5,
	maxRetransmit: 4,
};
const TOKEN_LENGTH = 4;
/** How many concurrent messages are allowed. Should be 1 */
const MAX_CONCURRENCY = 1;

function incrementToken(token: Buffer): Buffer {
	const len = token.length;
	const ret = Buffer.alloc(len, token);
	for (let i = len - 1; i >= 0; i--) {
		if (ret[i] < 0xff) {
			ret[i]++;
			break;
		} else {
			ret[i] = 0;
			// continue with the next digit
		}
	}
	return ret;
}

function incrementMessageID(msgId: number): number {
	return (++msgId > 0xffff) ? 1 : msgId;
}

function findOption(opts: Option[], name: string): Option {
	for (const opt of opts) {
		if (opt.name === name) return opt;
	}
}

function findOptions(opts: Option[], name: string): Option[] {
	return opts.filter(opt => opt.name === name);
}

/**
 * provides methods to access CoAP server resources
 */
export class CoapClient {

	/** Table of all open connections and their parameters, sorted by the origin "coap(s)://host:port" */
	private static connections: { [origin: string]: ConnectionInfo } = {};
	/** Queue of the connections waiting to be established */
	private static pendingConnections: { [origin: string]: DeferredPromise<ConnectionInfo> } = {};
	private static isConnecting: boolean = false;
	/** Table of all known security params, sorted by the hostname */
	private static dtlsParams: { [hostname: string]: SecurityParameters } = {};
	/** All pending requests, sorted by the token */
	private static pendingRequestsByToken: { [token: string]: PendingRequest } = {};
	private static pendingRequestsByMsgID: { [msgId: number]: PendingRequest } = {};
	private static pendingRequestsByUrl: { [url: string]: PendingRequest } = {};
	/** Queue of the messages waiting to be sent */
	private static sendQueue: QueuedMessage[] = [];
	/** Number of message we expect an answer for */
	private static concurrency: number = 0;

	/**
	 * Sets the security params to be used for the given hostname
	 */
	public static setSecurityParams(hostname: string, params: SecurityParameters) {
		CoapClient.dtlsParams[hostname] = params;
	}

	/**
	 * Closes and forgets about connections, useful if DTLS session is reset on remote end
	 * @param originOrHostname - Origin (protocol://hostname:port) or Hostname to reset,
	 * omit to reset all connections
	 */
	public static reset(originOrHostname?: string | Origin) {
		debug(`reset(${originOrHostname || ""})`);
		let predicate: (originString: string) => boolean;
		if (originOrHostname != null) {
			if (typeof originOrHostname === "string") {
				// we were given a hostname, forget the connection if the origin's hostname matches
				predicate = (originString: string) => Origin.parse(originString).hostname === originOrHostname;
			} else {
				// we were given an origin, forget the connection if its string representation matches
				const match = originOrHostname.toString();
				predicate = (originString: string) => originString === match;
			}
		} else {
			// we weren't given a filter, forget all connections
			predicate = (originString: string) => true;
		}

		// forget all pending requests matching the predicate
		for (const msgId of Object.keys(CoapClient.pendingRequestsByMsgID)) {
			// check if the request matches the predicate
			const request: PendingRequest = CoapClient.pendingRequestsByMsgID[msgId];
			const originString = Origin.parse(request.url).toString();
			if (!predicate(originString)) continue;

			// and forget it if so
			if (request.promise != null) (request.promise as DeferredPromise<CoapResponse>).reject("CoapClient was reset");
			CoapClient.forgetRequest({ request });
		}
		debug(`${Object.keys(CoapClient.pendingRequestsByMsgID).length} pending requests remaining...`);

		// cancel all pending connections matching the predicate
		for (const originString of Object.keys(CoapClient.pendingConnections)) {
			if (!predicate(originString)) continue;

			CoapClient.pendingConnections[originString].reject("CoapClient was reset");
			delete CoapClient.pendingConnections[originString];
		}
		debug(`${Object.keys(CoapClient.pendingConnections).length} pending connections remaining...`);

		// forget all connections matching the predicate
		for (const originString of Object.keys(CoapClient.connections)) {
			if (!predicate(originString)) continue;

			debug(`closing connection to ${originString}`);
			if (CoapClient.connections[originString].socket) {
				CoapClient.connections[originString].socket.close();
			}
			delete CoapClient.connections[originString];
		}
		debug(`${Object.keys(CoapClient.connections).length} active connections remaining...`);
	}

	/**
	 * Requests a CoAP resource
	 * @param url - The URL to be requested. Must start with coap:// or coaps://
	 * @param method - The request method to be used
	 * @param payload - The optional payload to be attached to the request
	 * @param options - Various options to control the request.
	 */
	public static async request(
		url: string | nodeUrl.Url,
		method: RequestMethod,
		payload?: Buffer,
		options?: RequestOptions,
	): Promise<CoapResponse> {

		// parse/convert url
		if (typeof url === "string") {
			url = nodeUrl.parse(url);
		}

		// ensure we have options and set the default params
		options = options || {};
		if (options.confirmable == null) options.confirmable = true;
		if (options.keepAlive == null) options.keepAlive = true;
		if (options.retransmit == null) options.retransmit = true;

		// retrieve or create the connection we're going to use
		const origin = Origin.fromUrl(url);
		const originString = origin.toString();
		const connection = await CoapClient.getConnection(origin);

		// find all the message parameters
		const type = options.confirmable ? MessageType.CON : MessageType.NON;
		const code = MessageCodes.request[method];
		const messageId = connection.lastMsgId = incrementMessageID(connection.lastMsgId);
		const token = connection.lastToken = incrementToken(connection.lastToken);
		const tokenString = token.toString("hex");
		payload = payload || Buffer.from([]);

		// create message options, be careful to order them by code, no sorting is implemented yet
		const msgOptions: Option[] = [];
		//// [6] observe or not?
		// msgOptions.push(Options.Observe(options.observe))
		// [11] path of the request
		let pathname = url.pathname || "";
		while (pathname.startsWith("/")) { pathname = pathname.slice(1); }
		while (pathname.endsWith("/")) { pathname = pathname.slice(0, -1); }
		const pathParts = pathname.split("/");
		msgOptions.push(
			...pathParts.map(part => Options.UriPath(part)),
		);
		// [12] content format
		msgOptions.push(Options.ContentFormat(ContentFormats.application_json));

		// create the promise we're going to return
		const response = createDeferredPromise<CoapResponse>();

		// create the message we're going to send
		const message = CoapClient.createMessage(type, code, messageId, token, msgOptions, payload);

		// create the retransmission info
		let retransmit: RetransmissionInfo;
		if (options.retransmit && type === MessageType.CON) {
			const timeout = CoapClient.getRetransmissionInterval();
			retransmit = {
				timeout,
				action: () => CoapClient.retransmit(messageId),
				jsTimeout: null,
				counter: 0,
			};
		}

		// remember the request
		const req = new PendingRequest({
			connection,
			url: urlToString(url), // normalizedUrl
			originalMessage: message,
			retransmit,
			keepAlive: options.keepAlive,
			callback: null,
			observe: false,
			promise: response,
			concurrency: 0,
		});
		// remember the request
		CoapClient.rememberRequest(req);

		// now send the message
		CoapClient.send(connection, message);

		return response;

	}

	/**
	 * Pings a CoAP endpoint to check if it is alive
	 * @param target - The target to be pinged. Must be a string, NodeJS.Url or Origin and has to contain the protocol, host and port.
	 * @param timeout - (optional) Timeout in ms, after which the ping is deemed unanswered. Default: 5000ms
	 */
	public static async ping(
		target: string | nodeUrl.Url | Origin,
		timeout: number = 5000,
	): Promise<boolean> {

		// parse/convert url
		if (typeof target === "string") {
			target = Origin.parse(target);
		} else if (!(target instanceof Origin)) { // is a nodeUrl
			target = Origin.fromUrl(target);
		}

		// retrieve or create the connection we're going to use
		const originString = target.toString();
		let connection: ConnectionInfo;
		try {
			connection = await CoapClient.getConnection(target);
		} catch (e) {
			// we didn't even get a connection, so fail the ping
			return false;
		}

		// create the promise we're going to return
		const response = createDeferredPromise<CoapResponse>();

		// create the message we're going to send.
		// An empty message with type CON equals a ping and provokes a RST from the server
		const messageId = connection.lastMsgId = incrementMessageID(connection.lastMsgId);
		const message = CoapClient.createMessage(
			MessageType.CON,
			MessageCodes.empty,
			messageId,
		);

		// remember the request
		const req = new PendingRequest({
			connection,
			url: originString,
			originalMessage: message,
			retransmit: null,
			keepAlive: true,
			callback: null,
			observe: false,
			promise: response,
			concurrency: 0,
		});
		// remember the request
		CoapClient.rememberRequest(req);

		// now send the message
		CoapClient.send(connection, message);
		// fail the ping after the timeout has passed
		const failTimeout = setTimeout(() => response.reject(), timeout);

		let success: boolean;
		try {
			// now wait for success or failure
			await response;
			success = true;
		} catch (e) {
			success = false;
		} finally {
			// cleanup
			clearTimeout(failTimeout);
			CoapClient.forgetRequest({request: req});
		}

		return success;
	}

	/**
	 * Re-Sends a message in case it got lost
	 * @param msgID
	 */
	private static retransmit(msgID: number) {
		// find the request with all the information
		const request = CoapClient.findRequest({ msgID });
		if (request == null || request.retransmit == null) return;

		// are we over the limit?
		if (request.retransmit.counter > RETRANSMISSION_PARAMS.maxRetransmit) {
			// if this is a one-time request, reject the response promise
			if (request.promise !== null) {
				(request.promise as DeferredPromise<CoapResponse>).reject(new Error("Retransmit counter exceeded"));
			}
			// then stop retransmitting and forget the request
			CoapClient.forgetRequest({ request });
			return;
		}

		debug(`retransmitting message ${msgID.toString(16)}, try #${request.retransmit.counter + 1}`);

		// resend the message
		CoapClient.send(request.connection, request.originalMessage, true);
		// and increase the params
		request.retransmit.counter++;
		request.retransmit.timeout *= 2;
		request.queueForRetransmission();
	}
	private static getRetransmissionInterval(): number {
		return Math.round(1000 /*ms*/ * RETRANSMISSION_PARAMS.ackTimeout *
			(1 + Math.random() * (RETRANSMISSION_PARAMS.ackRandomFactor - 1)),
		);
	}
	private static stopRetransmission(request: PendingRequest) {
		if (request.retransmit == null) return;
		clearTimeout(request.retransmit.jsTimeout);
		request.retransmit = null;
	}

	/**
	 * Observes a CoAP resource
	 * @param url - The URL to be requested. Must start with coap:// or coaps://
	 * @param method - The request method to be used
	 * @param payload - The optional payload to be attached to the request
	 * @param options - Various options to control the request.
	 */
	public static async observe(
		url: string | nodeUrl.Url,
		method: RequestMethod,
		callback: (resp: CoapResponse) => void,
		payload?: Buffer,
		options?: RequestOptions,
	): Promise<void> {

		// parse/convert url
		if (typeof url === "string") {
			url = nodeUrl.parse(url);
		}

		// ensure we have options and set the default params
		options = options || {};
		if (options.confirmable == null) options.confirmable = true;
		if (options.keepAlive == null) options.keepAlive = true;
		if (options.retransmit == null) options.retransmit = true;

		// retrieve or create the connection we're going to use
		const origin = Origin.fromUrl(url);
		const originString = origin.toString();
		const connection = await CoapClient.getConnection(origin);

		// find all the message parameters
		const type = options.confirmable ? MessageType.CON : MessageType.NON;
		const code = MessageCodes.request[method];
		const messageId = connection.lastMsgId = incrementMessageID(connection.lastMsgId);
		const token = connection.lastToken = incrementToken(connection.lastToken);
		const tokenString = token.toString("hex");
		payload = payload || Buffer.from([]);

		// create message options, be careful to order them by code, no sorting is implemented yet
		const msgOptions: Option[] = [];
		// [6] observe?
		msgOptions.push(Options.Observe(true));
		// [11] path of the request
		let pathname = url.pathname || "";
		while (pathname.startsWith("/")) { pathname = pathname.slice(1); }
		while (pathname.endsWith("/")) { pathname = pathname.slice(0, -1); }
		const pathParts = pathname.split("/");
		msgOptions.push(
			...pathParts.map(part => Options.UriPath(part)),
		);
		// [12] content format
		msgOptions.push(Options.ContentFormat(ContentFormats.application_json));

		// create the promise we're going to return
		const response = createDeferredPromise<CoapResponse>();

		// create the message we're going to send
		const message = CoapClient.createMessage(type, code, messageId, token, msgOptions, payload);

		// create the retransmission info
		let retransmit: RetransmissionInfo;
		if (options.retransmit && type === MessageType.CON) {
			const timeout = CoapClient.getRetransmissionInterval();
			retransmit = {
				timeout,
				action: () => CoapClient.retransmit(messageId),
				jsTimeout: null,
				counter: 0,
			};
		}

		// remember the request
		const req = new PendingRequest({
			connection,
			url: urlToString(url), // normalizedUrl
			originalMessage: message,
			retransmit,
			keepAlive: options.keepAlive,
			callback,
			observe: true,
			promise: null,
			concurrency: 0,
		});
		// remember the request
		CoapClient.rememberRequest(req);

		// now send the message
		CoapClient.send(connection, message);

	}

	/**
	 * Stops observation of the given url
	 */
	public static stopObserving(url: string | nodeUrl.Url) {

		// parse/convert url
		if (typeof url === "string") {
			url = nodeUrl.parse(url);
		}

		// normalize the url
		const urlString = urlToString(url);
		// and forget the request if we have one remembered
		CoapClient.forgetRequest({ url: urlString });
	}

	private static onMessage(origin: string, message: Buffer, rinfo: dgram.RemoteInfo) {
		// parse the CoAP message
		const coapMsg = Message.parse(message);
		debug(`received message: ID=0x${coapMsg.messageId.toString(16)}${(coapMsg.token && coapMsg.token.length) ? (", token=" + coapMsg.token.toString("hex")) : ""}`);

		if (coapMsg.code.isEmpty()) {
			// ACK or RST
			// see if we have a request for this message id
			const request = CoapClient.findRequest({ msgID: coapMsg.messageId });
			if (request != null) {
				// reduce the request's concurrency, since it was handled on the server
				request.concurrency = 0;
				// handle the message
				switch (coapMsg.type) {
					case MessageType.ACK:
						debug(`received ACK for message 0x${coapMsg.messageId.toString(16)}, stopping retransmission...`);
						// the other party has received the message, stop resending
						CoapClient.stopRetransmission(request);
						break;

					case MessageType.RST:
						if (
							request.originalMessage.type === MessageType.CON &&
							request.originalMessage.code === MessageCodes.empty
						) { // this message was a ping (empty CON, answered by RST)
							// resolve the promise
							debug(`received response to ping with ID 0x${coapMsg.messageId.toString(16)}`);
							(request.promise as DeferredPromise<CoapResponse>).resolve();
						} else {
							// the other party doesn't know what to do with the request, forget it
							debug(`received RST for message 0x${coapMsg.messageId.toString(16)}, forgetting the request...`);
							CoapClient.forgetRequest({ request });
						}
						break;
				}
			}
		} else if (coapMsg.code.isRequest()) {
			// we are a client implementation, we should not get requests
			// ignore them
		} else if (coapMsg.code.isResponse()) {
			debug(`response with payload: ${coapMsg.payload.toString("utf8")}`);
			// this is a response, find out what to do with it
			if (coapMsg.token && coapMsg.token.length) {
				// this message has a token, check which request it belongs to
				const tokenString = coapMsg.token.toString("hex");
				const request = CoapClient.findRequest({ token: tokenString });
				if (request) {

					// if the message is an acknowledgement, stop resending
					if (coapMsg.type === MessageType.ACK) {
						debug(`received ACK for message 0x${coapMsg.messageId.toString(16)}, stopping retransmission...`);
						CoapClient.stopRetransmission(request);
						// reduce the request's concurrency, since it was handled on the server
						request.concurrency = 0;
					}

					// parse options
					let contentFormat: ContentFormats = null;
					if (coapMsg.options && coapMsg.options.length) {
						// see if the response contains information about the content format
						const optCntFmt = findOption(coapMsg.options, "Content-Format");
						if (optCntFmt) contentFormat = (optCntFmt as NumericOption).value;
					}

					// prepare the response
					const response: CoapResponse = {
						code: coapMsg.code,
						format: contentFormat,
						payload: coapMsg.payload,
					};

					if (request.observe) {
						// call the callback
						request.callback(response);
					} else {
						// resolve the promise
						(request.promise as DeferredPromise<CoapResponse>).resolve(response);
						// after handling one-time requests, delete the info about them
						CoapClient.forgetRequest({ request });
					}

					// also acknowledge the packet if neccessary
					if (coapMsg.type === MessageType.CON) {
						debug(`sending ACK for message 0x${coapMsg.messageId.toString(16)}`);
						const ACK = CoapClient.createMessage(
							MessageType.ACK,
							MessageCodes.empty,
							coapMsg.messageId,
						);
						CoapClient.send(request.connection, ACK, true);
					}

				} else { // request == null
					// no request found for this token, send RST so the server stops sending

					// try to find the connection that belongs to this origin
					const originString = origin.toString();
					if (CoapClient.connections.hasOwnProperty(originString)) {
						const connection = CoapClient.connections[originString];

						// and send the reset
						debug(`sending RST for message 0x${coapMsg.messageId.toString(16)}`);
						const RST = CoapClient.createMessage(
							MessageType.RST,
							MessageCodes.empty,
							coapMsg.messageId,
						);
						CoapClient.send(connection, RST, true);
					}
				} // request != null?
			} // (coapMsg.token && coapMsg.token.length)

		} // (coapMsg.code.isResponse())
	}

	/**
	 * Creates a message with the given parameters
	 * @param type
	 * @param code
	 * @param messageId
	 * @param token
	 * @param options
	 * @param payload
	 */
	private static createMessage(
		type: MessageType,
		code: MessageCode,
		messageId: number,
		token: Buffer = null,
		options: Option[] = [], // do we need this?
		payload: Buffer = null,
	): Message {
		return new Message(
			0x01,
			type, code, messageId, token, options, payload,
		);
	}

	/**
	 * Send a CoAP message to the given endpoint
	 * @param connection The connection to send the message on
	 * @param message The message to send
	 * @param highPriority Whether the message should be prioritized
	 */
	private static send(
		connection: ConnectionInfo,
		message: Message,
		highPriority: boolean = false,
	): void {

		const request = CoapClient.findRequest({msgID: message.messageId});

		if (highPriority) {
			// Send high-prio messages immediately
			debug(`sending high priority message 0x${message.messageId.toString(16)}`);
			CoapClient.doSend(connection, request, message);
		} else {
			// Put the message in the queue
			CoapClient.sendQueue.push({connection, message});
			debug(`added message to send queue, new length = ${CoapClient.sendQueue.length}`);
		}

		// if there's a request for this message, listen for concurrency changes
		if (request != null) {
			// and continue working off the queue when it drops
			request.on("concurrencyChanged", (req: PendingRequest) => {
				debug(`request 0x${message.messageId.toString(16)}: concurrency changed => ${req.concurrency}`);
				if (request.concurrency === 0) CoapClient.workOffSendQueue();
			});
		}

		// start working it off now (maybe)
		CoapClient.workOffSendQueue();
	}
	private static workOffSendQueue() {

		// check if there are messages to send
		if (CoapClient.sendQueue.length === 0) {
			debug(`workOffSendQueue > queue empty`);
			return;
		}

		// check if we may send a message now
		debug(`workOffSendQueue > concurrency = ${CoapClient.calculateConcurrency()} (MAX ${MAX_CONCURRENCY})`);
		if (CoapClient.calculateConcurrency() < MAX_CONCURRENCY) {
			// get the next message to send
			const { connection, message } = CoapClient.sendQueue.shift();
			debug(`concurrency low enough, sending message 0x${message.messageId.toString(16)}`);
			// update the request's concurrency (it's now being handled)
			const request = CoapClient.findRequest({ msgID: message.messageId });
			CoapClient.doSend(connection, request, message);
		}

		// to avoid any deadlocks we didn't think of, re-call this later
		setTimeout(CoapClient.workOffSendQueue, 1000);
	}

	/**
	 * Does the actual sending of a message and starts concurrency/retransmission handling
	 */
	private static doSend(
		connection: ConnectionInfo,
		request: PendingRequest,
		message: Message,
	): void {
		// handle concurrency/retransmission if neccessary
		if (request != null) {
			request.concurrency = 1;
			request.queueForRetransmission();
		}
		// send the message
		connection.socket.send(message.serialize(), connection.origin);
	}

	/** Calculates the current concurrency, i.e. how many parallel requests are being handled */
	private static calculateConcurrency(): number {
		return Object.keys(CoapClient.pendingRequestsByMsgID)		// find all requests
			.map(msgid => CoapClient.pendingRequestsByMsgID[msgid])
			.map(req => req.concurrency)							// extract their concurrency
			.reduce((sum, item) => sum + item, 0)					// and sum it up
			;
	}

	/**
	 * Remembers a request for resending lost messages and tracking responses and updates
	 * @param request
	 * @param byUrl
	 * @param byMsgID
	 * @param byToken
	 */
	private static rememberRequest(
		request: PendingRequest,
		byUrl: boolean = true,
		byMsgID: boolean = true,
		byToken: boolean = true,
	) {
		let tokenString: string = "";
		if (byToken && request.originalMessage.token != null) {
			tokenString = request.originalMessage.token.toString("hex");
			CoapClient.pendingRequestsByToken[tokenString] = request;
		}
		if (byMsgID) {
			CoapClient.pendingRequestsByMsgID[request.originalMessage.messageId] = request;
		}
		if (byUrl) {
			CoapClient.pendingRequestsByUrl[request.url] = request;
		}
		debug(`remembering request: msgID=0x${request.originalMessage.messageId.toString(16)}, token=${tokenString}, url=${request.url}`);
	}

	/**
	 * Forgets a pending request
	 * @param request
	 * @param byUrl
	 * @param byMsgID
	 * @param byToken
	 */
	private static forgetRequest(
		which: {
			request?: PendingRequest,
			url?: string,
			msgID?: number,
			token?: string,
		}) {

		// find the request
		const request = which.request || CoapClient.findRequest(which);

		// none found, return
		if (request == null) return;

		let tokenString: string = "";
		if (request.originalMessage.token != null) {
			tokenString = request.originalMessage.token.toString("hex");
		}
		const msgID = request.originalMessage.messageId;

		debug(`forgetting request: token=${tokenString}; msgID=0x${msgID.toString(16)}`);

		// stop retransmission if neccessary
		CoapClient.stopRetransmission(request);

		// delete all references
		if (CoapClient.pendingRequestsByToken.hasOwnProperty(tokenString)) {
			delete CoapClient.pendingRequestsByToken[tokenString];
		}

		if (CoapClient.pendingRequestsByMsgID.hasOwnProperty(msgID)) {
			delete CoapClient.pendingRequestsByMsgID[msgID];
		}

		if (CoapClient.pendingRequestsByUrl.hasOwnProperty(request.url)) {
			delete CoapClient.pendingRequestsByUrl[request.url];
		}

		// Set concurrency to 0, so the send queue can continue
		request.concurrency = 0;
		// Clean up the event listeners
		request.removeAllListeners();

		// If this request doesn't have the keepAlive option,
		// close the connection if it was the last one with the same origin
		if (!request.keepAlive) {
			const origin = Origin.parse(request.url);
			const requestsOnOrigin: number = CoapClient.findRequestsByOrigin(origin).length;
			if (requestsOnOrigin === 0) {
				// this was the last request, close the connection
				CoapClient.reset(origin);
			}
		}

	}

	/**
	 * Finds a request we have remembered by one of its properties
	 * @param which
	 */
	private static findRequest(
		which: {
			url?: string,
			msgID?: number,
			token?: string,
		},
	): PendingRequest {

		if (which.url != null) {
			if (CoapClient.pendingRequestsByUrl.hasOwnProperty(which.url)) {
				return CoapClient.pendingRequestsByUrl[which.url];
			}
		} else if (which.msgID != null) {
			if (CoapClient.pendingRequestsByMsgID.hasOwnProperty(which.msgID)) {
				return CoapClient.pendingRequestsByMsgID[which.msgID];
			}
		} else if (which.token != null) {
			if (CoapClient.pendingRequestsByToken.hasOwnProperty(which.token)) {
				return CoapClient.pendingRequestsByToken[which.token];
			}
		}

		return null;
	}

	/**
	 * Finds all pending requests of a given origin
	 */
	private static findRequestsByOrigin(origin: Origin): PendingRequest[] {
		const originString = origin.toString();
		return Object
			.keys(CoapClient.pendingRequestsByMsgID)
			.map(msgID => CoapClient.pendingRequestsByMsgID[msgID])
			.filter((req: PendingRequest) => Origin.parse(req.url).toString() === originString)
			;
	}

	/**
	 * Tries to establish a connection to the given target. Returns true on success, false otherwise.
	 * @param target The target to connect to. Must be a string, NodeJS.Url or Origin and has to contain the protocol, host and port.
	 */
	public static async tryToConnect(target: string | nodeUrl.Url | Origin): Promise<boolean> {
		// parse/convert url
		if (typeof target === "string") {
			target = Origin.parse(target);
		} else if (!(target instanceof Origin)) { // is a nodeUrl
			target = Origin.fromUrl(target);
		}

		// retrieve or create the connection we're going to use
		const originString = target.toString();
		try {
			await CoapClient.getConnection(target);
			return true;
		} catch (e) {
			return false;
		}
	}

	/**
	 * Establishes a new or retrieves an existing connection to the given origin
	 * @param origin - The other party
	 */
	private static getConnection(origin: Origin): Promise<ConnectionInfo> {
		const originString = origin.toString();
		if (CoapClient.connections.hasOwnProperty(originString)) {
			debug(`getConnection(${originString}) => found existing connection`);
			// return existing connection
			return Promise.resolve(CoapClient.connections[originString]);
		} else if (CoapClient.pendingConnections.hasOwnProperty(originString)) {
			debug(`getConnection(${originString}) => connection is pending`);
			// return the pending connection
			return CoapClient.pendingConnections[originString];
		} else {
			debug(`getConnection(${originString}) => establishing new connection`);
			// create a promise and start the connection queue
			const ret = createDeferredPromise<ConnectionInfo>();
			CoapClient.pendingConnections[originString] = ret;
			setTimeout(CoapClient.workOffPendingConnections, 0);
			return ret;
		}
	}

	private static async workOffPendingConnections(): Promise<void> {

		if (Object.keys(CoapClient.pendingConnections).length === 0) {
			// no more pending connections, we're done
			CoapClient.isConnecting = false;
			return;
		} else if (CoapClient.isConnecting) {
			// we're already busy
			return;
		}
		CoapClient.isConnecting = true;

		// Get the connection to establish
		const originString = Object.keys(CoapClient.pendingConnections)[0];
		const origin = Origin.parse(originString);
		const promise = CoapClient.pendingConnections[originString];
		delete CoapClient.pendingConnections[originString];

		// Try a few times to setup a working connection
		const maxTries = 3;
		let socket: SocketWrapper;
		for (let i = 1; i <= maxTries; i++) {
			try {
				socket = await CoapClient.getSocket(origin);
				break; // it worked
			} catch (e) {
				// if we are going to try again, ignore the error
				// else throw it
				if (i === maxTries) {
					promise.reject(e);
				}
			}
		}

		if (socket != null) {
			// add the event handler
			socket.on("message", CoapClient.onMessage.bind(CoapClient, originString));
			// initialize the connection params and remember them
			const ret = CoapClient.connections[originString] = {
				origin,
				socket,
				lastMsgId: 0,
				lastToken: crypto.randomBytes(TOKEN_LENGTH),
			};
			// and resolve the deferred promise
			promise.resolve(ret);
		}

		// continue working off the queue
		CoapClient.isConnecting = false;
		setTimeout(CoapClient.workOffPendingConnections, 0);
	}

	/**
	 * Establishes or retrieves a socket that can be used to send to and receive data from the given origin
	 * @param origin - The other party
	 */
	private static async getSocket(origin: Origin): Promise<SocketWrapper> {

		switch (origin.protocol) {
			case "coap:":
				// simply return a normal udp socket
				return Promise.resolve(new SocketWrapper(dgram.createSocket("udp4")));
			case "coaps:":
				// return a promise we resolve as soon as the connection is secured
				const ret = createDeferredPromise<SocketWrapper>();
				// try to find security parameters
				if (!CoapClient.dtlsParams.hasOwnProperty(origin.hostname)) {
					return Promise.reject(`No security parameters given for the resource at ${origin.toString()}`);
				}
				const dtlsOpts: dtls.Options = Object.assign(
					({
						type: "udp4",
						address: origin.hostname,
						port: origin.port,
					} as dtls.Options),
					CoapClient.dtlsParams[origin.hostname],
				);
				// try connecting
				const onConnection = () => {
					debug("successfully created socket for origin " + origin.toString());
					sock.removeListener("error", onError);
					ret.resolve(new SocketWrapper(sock));
				};
				const onError = (e: Error) => {
					debug("socket creation for origin " + origin.toString() + " failed: " + e);
					sock.removeListener("connected", onConnection);
					ret.reject(e.message);
				};
				const sock = dtls
					.createSocket(dtlsOpts)
					.once("connected", onConnection)
					.once("error", onError)
					;
				return ret;
			default:
				throw new Error(`protocol type "${origin.protocol}" is not supported`);
		}

	}

}
