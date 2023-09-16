// deno-lint-ignore-file

function setStatus(status) {
  document.getElementById("status").innerText = status;
}

/**
 * @returns {PublicKeyCredentialRequestOptions | null} credential options
 */
async function getOptions() {
  const getOptionsUrl = new URL(
    "/authentication/options",
    document.location,
  );
  getOptionsUrl.searchParams.set("passkey", "true");
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
    return null;
  }
  /** @type {{options: string}} */
  const json = await getOptionsResponse.json();
  if (!json.options) {
    setStatus("Could not begin authentication");
    return null;
  }
  /** @type {{PublicKeyCredentialRequestOptions}} */
  const authenticationOptions = parseWebAuthnObject(json.options);

  return authenticationOptions;
}

/**
 * @param {Uint8Array} credentialId
 * @param {AuthenticatorAssertionResponse} response
 */
async function sendAuthentication(credentialId, response) {
  const json = {
    credentialId: encodeBase64Url(credentialId),
    response: stringifyWebAuthnObject(response),
  };
  console.log("signature", encodeBase64Url(response.signature));
  const authenticationUrl = new URL(
    "/authentication/submit",
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

document.querySelector("#sign-in-passkey").addEventListener(
  "click",
  async () => {
    setStatus("");
    const options = await getOptions();
    if (!options) {
      return;
    }
    console.log(options);
    try {
      const credential = await navigator.credentials.get({
        publicKey: options,
      });
      console.log(credential);
      if (credential && credential.type == "public-key") {
        /** @type {PublicKeyCredential} */
        const publicKeyCredential = credential;
        /** @type {AuthenticatorAssertionResponse} */
        const response = publicKeyCredential.response;
        const status = await sendAuthentication(
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
          setStatus("Success");
          document.location = "/";
        }
      } else {
        setStatus("Failure, publicKey not found");
      }
    } catch (e) {
      if (e instanceof DOMException) {
        setStatus(e.message);
      } else if (e instanceof Error) {
        setStatus(e.message);
      } else {
        setStatus("an unknown error: " + e);
      }
    }
  },
);
