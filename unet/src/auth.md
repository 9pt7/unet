
Users are managed through an AWS Cognito user pool. Users can sign up with an
email and password, or through Google or Apple sign-in. The only information
required for signing up is an email. When the account is verified, the user
must specify a username before making authorized API calls. The user name has
the same constraints as a Unix username, and can be used as a file name. The
user name is stored in Cognito under the `preferred_username` claim (different
from the `username` claim, which is automatically set by Cognito and is
immutable).

A user can change their `preferred_username` as long as the new name is unique,
so it should not be used as a user ID. The `sub` claim in the token can instead
be used for identifying a user, and serves as the user ID.

A DynamoDB table is used for storing user data. The primary key is the user ID,
and there is a secondary index on the `preferred_username`.
