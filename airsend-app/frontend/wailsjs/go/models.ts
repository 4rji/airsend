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
	export class FileRecvResult {
	    filename: string;
	    size: number;
	    path: string;
	
	    static createFrom(source: any = {}) {
	        return new FileRecvResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.filename = source["filename"];
	        this.size = source["size"];
	        this.path = source["path"];
	    }
	}
	export class FileSendResult {
	    code: string;
	    filename: string;
	    size: number;
	
	    static createFrom(source: any = {}) {
	        return new FileSendResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.code = source["code"];
	        this.filename = source["filename"];
	        this.size = source["size"];
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

