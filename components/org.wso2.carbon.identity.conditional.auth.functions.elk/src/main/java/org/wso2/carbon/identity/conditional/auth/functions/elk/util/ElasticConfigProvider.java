package org.wso2.carbon.identity.conditional.auth.functions.elk.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Base64;
import java.util.Map;

import static org.wso2.carbon.identity.conditional.auth.functions.elk.util.ElasticConstants.ELASTIC_SEARCH_PATH;

public class ElasticConfigProvider {

    private static final String CONFIG_PATH = "../../risk_profile_query.txt";

    private static final String USERNAME = "[USERNAME]";

    private static final ElasticConfigProvider instance = new ElasticConfigProvider();

    private ElasticConfigProvider() {

    }

    public static ElasticConfigProvider getInstance() {

        return instance;
    }

    private String readConfigFile() throws IOException {
        String fileContent;

        InputStream is = getClass().getClassLoader().getResourceAsStream("queries/risk_profile_query.txt");

        if (is == null) {
            fileContent = "FILE READ FAILED";
        } else {
            InputStreamReader isReader = new InputStreamReader(is);
            BufferedReader reader = new BufferedReader(isReader);
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            fileContent = sb.toString();
        }

        return fileContent;
    }

    public String getElasticSearchUrl(String elasticDomain) {
        return "https://" + elasticDomain + ELASTIC_SEARCH_PATH;
    }

    public String getQuery(Map<String, String> params) throws IOException {
        String query = readConfigFile();

        query = query.replace(USERNAME, params.get("username"));

        return query;
    }

    public String getBasicAuthHeader(Map<String, String> params) {
        String toEncode = params.get("elasticUsername") + ":" + params.get("elasticPassword");
        return "Basic " + Base64.getEncoder().encodeToString(toEncode.getBytes());
    }

}
