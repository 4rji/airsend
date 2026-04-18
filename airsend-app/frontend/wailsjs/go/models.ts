export namespace main {
	
	export class ChatStatus {
	    connected: boolean;
	    code: string;
	
	    static createFrom(source: any = {}) {
	        return new ChatStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.connected = source["connected"];
	        this.code = source["code"];
	    }
	}
	export class ServerStatus {
	    running: boolean;
	    pid: number;
	    webUrl: string;
	    binary: string;
	
	    static createFrom(source: any = {}) {
	        return new ServerStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.pid = source["pid"];
	        this.webUrl = source["webUrl"];
	        this.binary = source["binary"];
	    }
	}

}

