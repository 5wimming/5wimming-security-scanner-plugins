/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.tsunami.plugins.detectors.exposedui.mywebservice;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.get;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects unauthenticated my webservice shell page. */
// 插件说明
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "MyWebserviceExposedUiDetector",
    version = "0.1",
    description =
        "This detector checks whether a unauthenticated my webservice is exposed. ",
    author = "5wiming",
    bootstrapModule = MyWebserviceExposedUiDetectorBootstrapModule.class)
public final class MyWebserviceExposedUiDetector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private final Clock utcClock;
  private final HttpClient httpClient;

  @Inject
  public MyWebserviceExposedUiDetector(@UtcClock Clock utcClock, HttpClient httpClient) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
  }

  // 关键函数，检测入口
  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting exposed ui detection for my webservice");
    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService) //判断是否为web服务
                .filter(this::isServiceVulnerable) //判断是否有漏洞
                .map(networkService -> buildDetectionReport(targetInfo, networkService)) //打印报告
                .collect(toImmutableList()))
        .build();
  }

  //漏洞检测函数
  private boolean isServiceVulnerable(NetworkService networkService) {
    String targetUri =
        NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + "hello";
    try {
      // This is a blocking call.
      HttpResponse response =
          httpClient.send(get(targetUri).withEmptyHeaders().build(), networkService);
      return response.status().isSuccess()
          // TODO(b/147455413): checking string is not needed once we have plugin
          // matching logic.
          && response
              .bodyString()
              .map(
                  body ->
                      body.contains("5wimming"))
              .orElse(false);
    } catch (IOException e) {
      logger.atWarning().withCause(e).log("Unable to query '%s'.", targetUri);
      return false;
    }
  }

  //打印报告
  private DetectionReport buildDetectionReport(
      TargetInfo scannedTarget, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(scannedTarget)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher("5wimming")
                        .setValue("MY_WEBSERVICE_EXPOSED_UI"))
                .setSeverity(Severity.CRITICAL)
                .setTitle("my webservice Exposed Ui")
                // TODO(b/147455413): determine CVSS score.
                .setDescription("my webservice is not password or token protected"))
        .build();
  }
}
