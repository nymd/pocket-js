/**
 *
 * StakingStatus enum with the possible Staking status values
 */
export enum StakingStatus {
    Unstaking = 1,
    Staked = 2
}
/**
 *
 * StakingStatus enum utility
 */
export namespace StakingStatus {
    /**
     *
     * Returns the StakingStatus by passing an string
     * @param {string} status - Staking status string.
     * @returns {StakingStatus} - StakingStatus object.
     * @memberof StakingStatus
     */
    export function getStatus(status: number): StakingStatus {
        switch (status) {
            case 1:
                return StakingStatus.Unstaking
            case 2:
                return StakingStatus.Staked
            default:
                return StakingStatus.Unstaking
        }
    }
}