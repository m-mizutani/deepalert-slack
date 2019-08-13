{
  build(DeepAlertStackName, SecretArn='', SlackURL='', LambdaRoleArn='', MessagePrefix='', IgnoreSeverity=''):: {
    local ReportTopic = {
      'Fn::ImportValue': DeepAlertStackName + '-ReportTopic',
    },

    AWSTemplateFormatVersion: '2010-09-09',
    Transform: 'AWS::Serverless-2016-10-31',

    Resources: {
      // --------------------------------------------------------
      // Lambda functions
      Handler: {
        Type: 'AWS::Serverless::Function',
        Properties: {
          CodeUri: 'build',
          Handler: 'main',
          Runtime: 'go1.x',
          Timeout: 30,
          MemorySize: 128,
          Role: (if LambdaRoleArn != '' then LambdaRoleArn else { Ref: 'LambdaRole' }),
          Environment: {
            Variables: {
              SECRET_ARN: SecretArn,
              SLACK_URL: SlackURL,
              MESSAGE_PREFIX: MessagePrefix,
              IGNORE_SEVERITY: IgnoreSeverity,
            },
          },
          Events: {
            NotifyTopic: {
              Type: 'SNS',
              Properties: {
                Topic: ReportTopic,
              },
            },
          },
        },
      },
    } + (if LambdaRoleArn != '' then {} else {
           // --------------------------------------------------------
           // Lambda IAM role
           LambdaRole: {
             Type: 'AWS::IAM::Role',
             Condition: 'LambdaRoleRequired',
             Properties: {
               AssumeRolePolicyDocument: {
                 Version: '2012-10-17',
                 Statement: [
                   {
                     Effect: 'Allow',
                     Principal: { Service: ['lambda.amazonaws.com'] },
                     Action: ['sts:AssumeRole'],
                   },
                 ],
                 Path: '/',
                 ManagedPolicyArns: ['arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'],
                 Policies: [
                   {
                     PolicyName: 'PublishReportContent',
                     PolicyDocument: {
                       Version: '2012-10-17',
                       Statement: [
                         {
                           Effect: 'Allow',
                           Action: ['secretsmanager:GetSecretValue'],
                           Resource: [SecretArn],
                         },
                       ],
                     },
                   },
                 ],
               },
             },
           },
         }),
  },
}
