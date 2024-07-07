import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions'; 
import { ZkpAuthCdkStack } from '../lib/zkp-auth-cdk-stack';

describe('ZKP Auth Stack', () => {
  let stack: Stack;

  beforeAll(() => {
    const app = new App();
    stack = new ZkpAuthCdkStack(app, 'ZkpAuthCdkStack');
  });

  it('creates a VPC', () => {
    const template = Template.fromStack(stack);
    template.resourceCountIs('AWS::EC2::VPC', 1);
  });

  it('creates an ECS cluster', () => {
    const template = Template.fromStack(stack);
    template.resourceCountIs('AWS::ECS::Cluster', 1);
  });

  it('creates a Fargate service for the server', () => {
    const template = Template.fromStack(stack);
    template.hasResourceProperties('AWS::ECS::Service', {
      LaunchType: 'FARGATE',
      DesiredCount: 1,
      TaskDefinition: {
        Ref: 'ZkpAuthServerTaskDef8E3B35E1', // Check your actual Ref value
      },
    });
  });

  it('creates a Fargate task definition for the server', () => {
    const template = Template.fromStack(stack);
    template.hasResourceProperties('AWS::ECS::TaskDefinition', {
      ContainerDefinitions: [
        {
          Name: 'ZkpAuthServerContainer', // Ensure the container name matches
          Command: ['server', '0.0.0.0', '50051'],
        },
      ],
    });
  });

  it('creates a Fargate task definition for the client', () => {
    const template = Template.fromStack(stack);
    template.hasResourceProperties('AWS::ECS::TaskDefinition', {
      ContainerDefinitions: [
        {
          Name: 'ZkpAuthClientContainer',  // Ensure the container name matches
          Command: ['sh', '-c', 'client ${ZKP_USERNAME} ${ZKP_AUTH_ALGO} ${SERVER_HOST} 50051'],
        },
      ],
    });
  });
});
