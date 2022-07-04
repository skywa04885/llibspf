import { IPv4Address, IPv6Address } from "llibipaddress";

export interface ISPFContextServer {
  hostname: string; // Our hostname.
}

export interface ISPFContextClient {
  ipAddress: IPv4Address | IPv6Address; // The remote address of the client.
  greetHostname: string; // The hostname received as argument in EHLO / HELO.
}

export interface ISPFContextMessage {
  emailUsername: string;
  emailDomain: string;
}

export interface ISPFContext {
  server: ISPFContextServer;
  client: ISPFContextClient;
  message: ISPFContextMessage;
}