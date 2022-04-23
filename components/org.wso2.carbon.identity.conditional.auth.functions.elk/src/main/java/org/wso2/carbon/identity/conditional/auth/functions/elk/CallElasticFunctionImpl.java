/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.elk;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.wso2.carbon.identity.conditional.auth.functions.elk.util.ElasticConfigProvider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.apache.http.HttpHeaders.*;
import static org.wso2.carbon.identity.conditional.auth.functions.elk.util.ElasticConstants.TYPE_APPLICATION_JSON;

/**
 * Implementation of the {@link CallElasticFunction}
 */
public class CallElasticFunctionImpl extends AbstractHTTPFunction implements CallElasticFunction {

    private static final Log LOG = LogFactory.getLog(CallElasticFunctionImpl.class);

    private static final ElasticConfigProvider elasticConfigProvider = ElasticConfigProvider.getInstance();
    public CallElasticFunctionImpl() {

        super();
    }

    @Override
    public void callElastic(String elasticDomain, Map<String, String> params, Map<String, Object> eventHandlers) {
        LOG.error("===== ELK CALLED =====");

        HttpPost request = new HttpPost(elasticConfigProvider.getElasticSearchUrl(elasticDomain));

        request.setHeader(ACCEPT, TYPE_APPLICATION_JSON);
        request.setHeader(CONTENT_TYPE, TYPE_APPLICATION_JSON);
        request.setHeader(AUTHORIZATION, elasticConfigProvider.getBasicAuthHeader(params));

        try {
            String query = elasticConfigProvider.getQuery(params);
            request.setEntity(new StringEntity(query, StandardCharsets.UTF_8));
        } catch (IOException exception) {
            LOG.error("Reading query config file failed");
        }
        executeHttpMethod(request, eventHandlers);
    }
}
