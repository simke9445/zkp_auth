import * as cdk from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as ecs from "aws-cdk-lib/aws-ecs";
import * as servicediscovery from "aws-cdk-lib/aws-servicediscovery";
import { Construct } from "constructs";

export class ZkpAuthCdkStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Create VPC
    const vpc = new ec2.Vpc(this, "ZkpAuthVpc", { maxAzs: 2 });

    // Create ECS Cluster
    const cluster = new ecs.Cluster(this, "ZkpAuthCluster", { vpc });

    // Create a Cloud Map namespace
    const namespace = new servicediscovery.PrivateDnsNamespace(
      this,
      "Namespace",
      {
        name: "service.local",
        vpc,
      }
    );

    // Server Task
    const serverTask = new ecs.FargateTaskDefinition(
      this,
      "ZkpAuthServerTaskDef",
      {
        cpu: 256,
        memoryLimitMiB: 512,
      }
    );

    const serverContainer = serverTask.addContainer("ZkpAuthServerContainer", {
      image: ecs.ContainerImage.fromAsset("../server"),
      logging: ecs.LogDrivers.awsLogs({ streamPrefix: "ZkpAuthServer" }),
      environment: {
        RUST_LOG: "info",
      },
      command: ["server", "0.0.0.0", "50051"],
    });

    serverContainer.addPortMappings({
      containerPort: 50051,
    });

    // Client Task
    const clientTask = new ecs.FargateTaskDefinition(
      this,
      "ZkpAuthClientTask",
      {
        cpu: 256,
        memoryLimitMiB: 512,
      }
    );

    const clientContainer = clientTask.addContainer("ZkpAuthClientContainer", {
      image: ecs.ContainerImage.fromAsset("../client"),
      environment: {
        RUST_LOG: "info",
        ZKP_USERNAME: "my_user",
        ZKP_AUTH_ALGO: "dl",
      },
      command: [
        "sh",
        "-c",
        "client ${ZKP_USERNAME} ${ZKP_AUTH_ALGO} ${SERVER_HOST} 50051",
      ],
    });

    // ECS Services
    const serverService = new ecs.FargateService(this, "ZkpAuthServerService", {
      cluster,
      taskDefinition: serverTask,
      desiredCount: 1,
      assignPublicIp: true, // Allow the server task to be reachable directly
      cloudMapOptions: {
        name: "server",
        cloudMapNamespace: namespace,
      },
    });

    // Set the SERVER_HOST environment variable after server service is created
    const serverServiceName =
      serverService.cloudMapService?.serviceName || "server";
    const serverNamespaceName = namespace.namespaceName;
    const serverHostname = `${serverServiceName}.${serverNamespaceName}`;

    clientContainer.addEnvironment("SERVER_HOST", serverHostname);

    const clientService = new ecs.FargateService(this, "ZkpAuthClientService", {
      cluster,
      taskDefinition: clientTask,
      desiredCount: 1,
      assignPublicIp: true, // Allow the client task to be reachable directly
    });

    // Output Server Hostname
    new cdk.CfnOutput(this, "ServerHostname", {
      value: serverHostname,
      description: "Server Hostname",
    });
  }
}
