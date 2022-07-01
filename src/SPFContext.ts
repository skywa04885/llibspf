import { IPv4Address, IPv6Address } from "llibipaddress";

export class SPFContext {
  public constructor(
    public readonly sender: string,
    public readonly senderDomain: string,
    public readonly clientDomain: string,
    public readonly clientIPAddress: IPv4Address | IPv6Address,
    public readonly clientGreetDomain: string,
    public readonly ourHostname: string,
  )  {}
}