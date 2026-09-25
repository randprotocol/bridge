// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.20;

/// The four Safe views `Governance.handoverFrom()` asks a multisig, and nothing else. Tests
/// `vm.etch` this runtime code onto an address and `vm.store` its slots; slot 0 is where a
/// real Safe proxy keeps its singleton (mastercopy).
contract FakeSafe {
    address internal singleton; // slot 0
    uint256 internal threshold; // slot 1
    uint256 internal ownerCount; // slot 2
    uint256 internal moduleCount; // slot 3

    function getThreshold() external view returns (uint256) {
        return threshold;
    }

    function getOwners() external view returns (address[] memory owners) {
        owners = new address[](ownerCount);
        for (uint256 i; i < ownerCount; i++) {
            owners[i] = address(uint160(0x5afe0000 + i));
        }
    }

    /// Safe's ModuleManager: `start` is the sentinel 0x1 for the first page.
    function getModulesPaginated(address start, uint256 pageSize)
        external
        view
        returns (address[] memory modules, address next)
    {
        require(start == address(0x1), "not the sentinel");
        uint256 n = moduleCount < pageSize ? moduleCount : pageSize;
        modules = new address[](n);
        for (uint256 i; i < n; i++) {
            modules[i] = address(uint160(0x3d0000 + i));
        }
        next = address(0x1);
    }
}
