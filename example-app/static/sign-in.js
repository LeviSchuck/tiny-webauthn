// deno-lint-ignore-file

function setStatus(status) {
  document.getElementById("status").innerText = status;
}

/**
 * @param {string} username
 * @returns {string[]} credential IDs
 */
async function getOptions(username) {
  const getOptionsUrl = new URL(
    "/authentication-options",
    document.location,
  );
  getOptionsUrl.searchParams.set("username", username);
  const getOptionsRequest = new Request(getOptionsUrl, { method: "POST" });
  getOptionsRequest.headers.set("Accept", "application/json");
  const getOptionsResponse = await fetch(getOptionsRequest);
  if (getOptionsResponse.status != 200) {
    console.error(getOptionsResponse);
    if (getOptionsResponse.headers.get("content-type") == "application/json") {
      const json = await getOptionsResponse.json();
      setStatus("Find Authenticators request failed: " + json.message);
    } else {
      setStatus("Find Authenticators request failed");
    }
    return [];
  }
  /** @type {{options: string}} */
  const json = await getOptionsResponse.json();
  if (!json.options) {
    throw new Error("Could not begin authentication");
  }
  /** @type {{PublicKeyCredentialRequestOptions}} */
  const authenticationOptions = parseWebAuthnObject(json.options);

  return authenticationOptions;
}

/**
 * @param {string} username
 * @param {Uint8Array} credentialId
 * @param {AuthenticatorAssertionResponse} response
 */
async function sendAuthentication(username, credentialId, response) {
  const json = {
    username: username,
    credentialId: encodeBase64Url(credentialId),
    response: stringifyWebAuthnObject(response),
  };
  console.log("signature", encodeBase64Url(response.signature));
  const authenticationUrl = new URL(
    "/authentication",
    document.location,
  );
  const authenticationRequest = new Request(authenticationUrl, {
    method: "POST",
    body: JSON.stringify(json),
    headers: new Headers([
      ["content-type", "application/json"],
    ]),
  });
  const authenticationResponse = await fetch(authenticationRequest);
  if (authenticationResponse.status != 200) {
    console.error(authenticationResponse);
    if (
      authenticationResponse.headers.get("content-type") == "application/json"
    ) {
      const json = await authenticationResponse.json();
      setStatus("Request failed: " + json.message);
    } else {
      setStatus("Request failed");
    }
    return false;
  }
  return true;
}

document.querySelector("#sign-in").addEventListener("click", async () => {
  setStatus("");
  const usernameField = document.getElementById("username");
  const username = usernameField.value;
  if (!username || username == "") {
    setStatus("Missing username");
    return;
  }
  const options = await getOptions(username);
  if (!options) {
    return;
  }
  console.log(options);
  const credential = await navigator.credentials.get({ publicKey: options });
  console.log(credential);
  if (credential && credential.type == "public-key") {
    /** @type {PublicKeyCredential} */
    const publicKeyCredential = credential;
    /** @type {AuthenticatorAssertionResponse} */
    const response = publicKeyCredential.response;
    const status = await sendAuthentication(
      username,
      publicKeyCredential.rawId,
      {
        signature: response.signature,
        authenticatorData: response.authenticatorData,
        attestationObject: response.attestationObject,
        clientDataJSON: response.clientDataJSON,
        userHandle: response.userHandle,
      },
    );
    if (status) {
      document.location = "/";
    }
  } else {
    setStatus("Failure, publicKey not found");
  }
});
