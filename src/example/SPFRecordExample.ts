import { SPFRecord } from "../SPFRecord";
import { SPFMacroProcessor } from "../SPFMacroProcessor";
import util from "util";
import { SPFContext } from "../SPFContext";
import { IPv4Address } from "llibipaddress";
import { SPFValidator } from "../SPFValidator";
import { MimeHeaders } from "llibmime";

(async () => {
  // console.log(await SPFRecord.resolve('fannst.nl'));
  // let processor = new SPFMacroProcessor('luke.rieff@gmail.com', 'fannst.nl',  '23.12.312','129.23.12.4', 'ipv4', 'gmail.com');
  // console.log(processor.process('%{s} %{o} %{d} %{d4} %{d3} %{d2} %{d1} %{d2r} %{l} %{l-} %{lr} %{lr-} %{l1r-} %% %- \'%_\' %{cr=} %{r} %{t}', true));
  try {
    const result = await new SPFValidator(
      new SPFContext(
        "luke.rieff@fannst.nl",
        "fannst.nl",
        "fannst.nl",
        IPv4Address.decode("207.180.225.138"),
        "fannst.nl",
        "fannst.nl"
      )
    ).validate("fannst.nl");

    const headers = new MimeHeaders();

    headers.set(...result.asHeader());

    console.log(headers.encode());
  } catch (e) {
    console.log(e);
  }
})();
