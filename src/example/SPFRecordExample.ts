import { IPv4Address } from "llibipaddress";
import { SPFValidator } from "../SPFValidator";
import { MimeHeaders } from "llibmime";
import winston from "winston";

const logger = winston.createLogger({
  transports: [
    new winston.transports.Console({
      level: 'debug',
      format: winston.format.combine(
        winston.format.timestamp({format: 'YYYY-MM-DD HH:mm:ss.SSS'}),
        winston.format.colorize(),
        winston.format.printf(({level, message, label, timestamp}) => `${timestamp} ${label || '-'} ${level}: ${message}`),
        )
    })
  ]
});

(async () => {
  // console.log(await SPFRecord.resolve('fannst.nl'));
  // let processor = new SPFMacroProcessor('luke.rieff@gmail.com', 'fannst.nl',  '23.12.312','129.23.12.4', 'ipv4', 'gmail.com');
  // console.log(processor.process('%{s} %{o} %{d} %{d4} %{d3} %{d2} %{d1} %{d2r} %{l} %{l-} %{lr} %{lr-} %{l1r-} %% %- \'%_\' %{cr=} %{r} %{t}', true));
  try {
    const result = await new SPFValidator(
      {
        message: {
          emailDomain: 'rijksoverheid.nl',
          emailUsername: 'luke.rieff'
        },
        client: {
          greetHostname: 'test123',
          ipAddress: IPv4Address.decode('29.85.216.54'),
        },
        server: {
          hostname: 'fannst.nl'
        }
      },
      logger
    ).validate();

    const headers = new MimeHeaders();

    headers.set(...result.asHeader());

    console.log(headers.encode());
  } catch (e) {
    console.log(e);
  }
})();
