# unet Deployment

Deployment steps:
- Build the Docker image
- Push the Docker image
- Cross-compile for each platform
- Deploy the CloudFormation stack

Development, staging, or production stacks are deployed, depending on
environemnt variables.
