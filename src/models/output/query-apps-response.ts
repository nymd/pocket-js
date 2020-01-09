import { Application } from "../application";
/**
 *
 *
 * @class QueryAppsResponse
 */
export class QueryAppsResponse {
    /**
   *
   * Creates a QueryAppsResponse object using a JSON string
   * @param {String} json - JSON string.
   * @returns {QueryAppsResponse} - QueryAppsResponse object.
   * @memberof QueryAppsResponse
   */
    public static fromJSON(json: string): QueryAppsResponse {
        const jsonObject = JSON.parse(json);
        let apps;

        jsonObject.forEach(function(appJSON: {}){
            let app = Application.fromJSON(JSON.stringify(appJSON));
            apps.push(app);
        }); 
        if (apps != undefined) {
            return new QueryAppsResponse(
                apps as Application[]
            ); 
        }else{
            // TODO: Handle undefined scenario properly
            return new QueryAppsResponse(
                jsonObject
            ); 
        }
    }

    public readonly applications: Application[];

    /**
     * QueryAppsResponse.
     * @constructor
     * @param {Application[]} applications - Amount staked by the node.
     */
    constructor(
        applications: Application[]
    ) {
        this.applications = applications
    }
    /**
   *
   * Creates a JSON object with the QueryAppsResponse properties
   * @returns {JSON} - JSON Object.
   * @memberof QueryAppsResponse
   */
    public toJSON() {
        var appListJSON;
        this.applications.forEach(app => {
            appListJSON.push(app.toJSON());
        });
        return {"apps": appListJSON}
    }
}