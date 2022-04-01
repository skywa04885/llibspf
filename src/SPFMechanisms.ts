import ipaddr from 'ipaddr.js';
import { SPFQualifier } from "./SPFRecord";

export interface SPFMechanismEvalArg {

}

export enum SPFMechanismResult {
  Pass,
  Fail,
  SoftFail,
  Neutral,
}

export class SPFMechanism {
  public evaluate(arg: SPFMechanismEvalArg): SPFMechanismResult {
    throw new Error("Not implemented!");
  }
}

export class SPFQualifierMechanism extends SPFMechanism {
  public constructor(
    public readonly qualifier: SPFQualifier = SPFQualifier.Pass
  ) {
    super();
  }
}

export class SPFQualifierWSpecMechanism extends SPFQualifierMechanism {
  public constructor(qualifier: SPFQualifier) {
    super(qualifier);
  }
}

export class SPFMechanismAll extends SPFQualifierMechanism {
  public evaluate(arg: SPFMechanismEvalArg): SPFMechanismResult {
    switch (this.qualifier) {
      case SPFQualifier.Pass:
        return SPFMechanismResult.Pass;
      case SPFQualifier.Fail:
        return SPFMechanismResult.Fail;
      case SPFQualifier.SoftFail:
        return SPFMechanismResult.SoftFail;
      case SPFQualifier.Neutral:
        return SPFMechanismResult.Neutral;
      default:
        throw new Error("Invalid qualifier.");
    }
  }
}

export class SPFMechanismInclude extends SPFQualifierMechanism {}

export class SPFMechanismA extends SPFQualifierMechanism {}

export class SPFMechanismMX extends SPFQualifierMechanism {}

export class SPFMechanismPTR extends SPFQualifierMechanism {}

export class SPFMechanismIPv4 extends SPFQualifierMechanism {

  public constructor(qualifier: SPFQualifier, cidr: string) {
    super(qualifier);

    ipaddr.parseCIDR(cidr);
  }
}

export class SPFMechanismIpv6 extends SPFQualifierMechanism {}

export class SPFMechanismExists extends SPFQualifierMechanism {}

export class SPFRecordCache {}
