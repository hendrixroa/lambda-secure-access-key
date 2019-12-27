const AWS = require('aws-sdk');
const FunctionShield = require('@puresec/function-shield');

const ENV = process.env;
const userToIgnore = ENV.userToIgnore;

FunctionShield.configure(
  {
    policy: {
      read_write_tmp: 'alert',
      create_child_process: 'alert',
      outbound_connectivity: 'alert',
      read_handler: 'alert'
    },
    disable_analytics: false,
    token: ENV.function_shield_token
  });

exports.handler = async (event, context) => {
  context.callbackWaitsForEmptyEventLoop = false;

  const today = new Date();

  try {
    const iam = new AWS.IAM();
    const iamUsers = await iam.listUsers({}).promise();
    const filteredUsers = iamUsers.Users.filter((user) => user.UserName !== userToIgnore ).map(user => user.UserName);
    for(const userName of filteredUsers){
      const accessKeys = await iam.listAccessKeys({ UserName: userName }).promise();
      for(const key of accessKeys.AccessKeyMetadata){
        const numDays = getDiffDays(new Date(key.CreateDate), today);
        if(numDays >= 90){
          // Make inactive the old key
          await iam
            .updateAccessKey({
              AccessKeyId: key.AccessKeyId,
              Status: 'Inactive',
              UserName: key.UserName,
            })
            .promise();

          // Delete old key
          await iam
            .deleteAccessKey({
              AccessKeyId: key.AccessKeyId,
              UserName: key.UserName,
            })
            .promise();

          console.log(`The key ${key.AccessKeyId} for the user ${key.UserName} has been deleted because the age is >= 90 days`);
        }
      }
    }

    return context.succeed();
  } catch (error) {
    console.log('Error deactivate keys: ', error);
    return context.fail(error); 
  }
};

function getDiffDays(dateStart, dateEnd) {
  return Math.floor(
    (Date.UTC(dateEnd.getFullYear(), dateEnd.getMonth(), dateEnd.getDate()) -
      Date.UTC(
        dateStart.getFullYear(),
        dateStart.getMonth(),
        dateStart.getDate(),
      )) /
    (1000 * 60 * 60 * 24),
  );
}
