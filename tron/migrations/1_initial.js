// TronBox (like the Truffle migration system it is forked from) expects a
// sequentially numbered migrations directory and, conventionally, a first
// migration that establishes the migrations-tracking baseline. This project
// deploys a single immutable contract and does not otherwise need on-chain
// migration tracking, so this step is intentionally a no-op -- it exists
// only so `tronbox migrate` has a "1_..." file to run before 2_deploy.js.
module.exports = function (_deployer, _network, _accounts) {
  // Nothing to do.
};
