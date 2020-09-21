/**
 * UsersController
 *
 * @description :: Server-side actions for handling incoming requests.
 * @help        :: See https://sailsjs.com/docs/concepts/actions
 */
const {
  // Registration ("Attestation")
  generateAttestationOptions,
  verifyAttestationResponse,
  // Login ("Assertion")
  generateAssertionOptions,
  verifyAssertionResponse,
} = require('@simplewebauthn/server');
//https://a1512284ee46.ngrok.io https://morning-river-88552.herokuapp.com/

const rpID = 'morning-river-88552.herokuapp.com';
const origin = `https://${rpID}`;
//const origin = `https://d42a2b1a8156.ngrok.io`;
console.log(rpID);




const loggedInUserId = 'internalUserId';

/**
 * You'll need a database to store a few things:
 *
 * 1. Users
 *
 * You'll need to be able to associate attestation and assertions challenges, and authenticators to
 * a specific user
 *
 * 2. Challenges
 *
 * The totally-random-unique-every-time values you pass into every execution of
 * `generateAttestationOptions()` or `generateAssertionOptions()` MUST be stored until
 * `verifyAttestationResponse()` or `verifyAssertionResponse()` (respectively) is called to verify
 * that the response contains the signed challenge.
 *
 * These values only need to be persisted for `timeout` number of milliseconds (see the `generate`
 * methods and their optional `timeout` parameter)
 *
 * 3. Authenticator Devices
 *
 * After an attestation, you'll need to store three things about the authenticator:
 *
 * - Base64-encoded "Credential ID" (varchar)
 * - Base64-encoded "Public Key" (varchar)
 * - Counter (int)
 *
 * Each authenticator must also be associated to a user so that you can generate a list of
 * authenticator credential IDs to pass into `generateAssertionOptions()`, from which one is
 * expected to generate an assertion response.
 */
const inMemoryUserDeviceDB = {
  [loggedInUserId]: {
    id: loggedInUserId,
    username: `user@${rpID}`,
    devices: [
      /**
       * {
       *   credentialID: string,
       *   publicKey: string,
       *   counter: number,
       * }
       */
    ],
    /**
     * A simple way of storing a user's current challenge being signed by attestation or assertion.
     * It should be expired after `timeout` milliseconds (optional argument for `generate` methods,
     * defaults to 60000ms)
     */
    currentChallenge: undefined,
  },
};
module.exports = {
/**
 * Registration (a.k.a. "Attestation")
 */
  generateattestationoptions: (req, res) => {
    const user = inMemoryUserDeviceDB[loggedInUserId];
    console.log('user /generate-attestation-options',user);
    const {
    /**
     * The username can be a human-readable name, email, etc... as it is intended only for display.
     */
      username,
      devices,
    } = user;

    const options = generateAttestationOptions({
      rpName: 'SimpleWebAuthn Example',
      rpID,
      userID: loggedInUserId,
      userName: username,
      timeout: 60000,
      attestationType: 'direct',
      /**
     * Passing in a user's list of already-registered authenticator IDs here prevents users from
     * registering the same device multiple times. The authenticator will simply throw an error in
     * the browser if it's asked to perform an attestation when one of these ID's already resides
     * on it.
     */
      excludedCredentialIDs: devices.map(dev => dev.credentialID),
      /**
     * The optional authenticatorSelection property allows for specifying more constraints around
     * the types of authenticators that users to can use for attestation
     */
      authenticatorSelection: {
        userVerification: 'preferred',
        requireResidentKey: false,
      },
    });

    /**
   * The server needs to temporarily remember this value for verification, so don't lose it until
   * after you verify an authenticator response.
   */
    inMemoryUserDeviceDB[loggedInUserId].currentChallenge = options.challenge;
    console.log('options /generate-attestation-options',options);
    res.send(options);
  },

  verifyattestation: async (req, res) => {
    const { body } = req;
    console.log(body);
    const user = inMemoryUserDeviceDB[loggedInUserId];

    const expectedChallenge = user.currentChallenge;

    let verification;
    try {
      verification = await verifyAttestationResponse({
        credential: body,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
      });
    } catch (error) {
      console.error(error);
      return res.status(400).send({ error: error.message });
    }

    const { verified, authenticatorInfo } = verification;

    if (verified) {
      const { base64PublicKey, base64CredentialID, counter } = authenticatorInfo;

      const existingDevice = user.devices.find(device => device.credentialID === base64CredentialID);

      if (!existingDevice) {
      /**
       * Add the returned device to the user's list of devices
       */
        user.devices.push({
          publicKey: base64PublicKey,
          credentialID: base64CredentialID,
          counter,
        });
      }
    }
    console.log('/verify-attestation',verification);
    res.send({ verified });
  },

  /**
 * Login (a.k.a. "Assertion")
 */
  generateassertionoptions: (req, res) => {
  // You need to know the user by this point
    const user = inMemoryUserDeviceDB[loggedInUserId];

    const options = generateAssertionOptions({
      timeout: 60000,
      allowedCredentialIDs: user.devices.map(data => data.credentialID),
      /**
     * This optional value controls whether or not the authenticator needs be able to uniquely
     * identify the user interacting with it (via built-in PIN pad, fingerprint scanner, etc...)
     */
      userVerification: 'preferred',
    });

    /**
   * The server needs to temporarily remember this value for verification, so don't lose it until
   * after you verify an authenticator response.
   */
    inMemoryUserDeviceDB[loggedInUserId].currentChallenge = options.challenge;

    res.send(options);
  },

  verifyassertion: (req, res) => {
    const { body } = req;

    const user = inMemoryUserDeviceDB[loggedInUserId];

    const expectedChallenge = user.currentChallenge;

    let dbAuthenticator;
    // "Query the DB" here for an authenticator matching `credentialID`
    for (let dev of user.devices) {
      if (dev.credentialID === body.id) {
        dbAuthenticator = dev;
        break;
      }
    }

    if (!dbAuthenticator) {
      throw new Error('could not find authenticator matching', body.id);
    }

    let verification;
    try {
      verification = verifyAssertionResponse({
        credential: body,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        authenticator: dbAuthenticator,
      });
    } catch (error) {
      console.error(error);
      return res.status(400).send({ error: error.message });
    }

    const { verified, authenticatorInfo } = verification;

    if (verified) {
    // Update the authenticator's counter in the DB to the newest count in the assertion
      dbAuthenticator.counter = authenticatorInfo.counter;
    }

    res.send({ verified });
  }
};
