// Copyright (c) iSPIRT Foundation.
// Licensed under the MIT license.
//
// DEPA Training v2 KMS — CCF JavaScript application entry point. Every export
// is referenced by a "js_function" in app.json.

import { receiptEndpoint } from "../packages/depa-ccf-common/src/index";
import { createDataset, getDataset, getDatasetPolicyHistory, resumeDataset, rotateDatasetKey, setDatasetPolicy, suspendDataset } from "./datasets";
import { getKeyRelease, releaseKeys } from "./key_release";
import { issueToken, oidcJwks, openidConfiguration } from "./oidc";
import { getOrCreateOutputKey, releaseOutputKey } from "./outputs";
import { governance, info } from "./service";

const gov = governance.endpoints;

export {
  info,
  receiptEndpoint as receipt,
  createDataset,
  getDataset,
  getDatasetPolicyHistory,
  setDatasetPolicy,
  rotateDatasetKey,
  suspendDataset,
  resumeDataset,
  releaseKeys,
  getKeyRelease,
  openidConfiguration,
  oidcJwks,
  issueToken,
  getOrCreateOutputKey,
  releaseOutputKey,
};

export const govBootstrap = gov.bootstrap;
export const govPropose = gov.propose;
export const govVote = gov.vote;
export const govListProposals = gov.listProposals;
export const govGetProposal = gov.getProposal;
export const govMembers = gov.members;
export const govConstitution = gov.constitution;
export const govState = gov.state;
export const listParties = gov.listParties;
export const getParty = gov.getParty;
export const listReleases = gov.listReleases;
export const getRelease = gov.getRelease;
