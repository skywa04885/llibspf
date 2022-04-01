import {SPFRecord} from "../SPFRecord";
import {SPFMacroProcessor} from "../SPFMacroProcessor";

(async () => {
  // console.log(await SPFRecord.resolve('fannst.nl'));
  let processor = new SPFMacroProcessor('luke.rieff@gmail.com', 'fannst.nl',  '23.12.312','129.23.12.4', 'ipv4', 'gmail.com');
  console.log(processor.process('%{s} %{o} %{d} %{d4} %{d3} %{d2} %{d1} %{d2r} %{l} %{l-} %{lr} %{lr-} %{l1r-} %% %- \'%_\' %{cr=} %{r} %{t}', true));
})();

