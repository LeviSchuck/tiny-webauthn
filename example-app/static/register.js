// deno-lint-ignore-file
function setStatus(status) {
  document.getElementById("status").innerText = status;
}

/**
 * @param {string} username
 * @param {boolean} passkey
 * @returns {{options: PublicKeyCredentialCreationOptions, authenticatingData: {challenge: string}}}
 */
async function getOptions(username, passkey) {
  const registrationOptionsUrl = new URL(
    "/registration/options",
    document.location,
  );
  registrationOptionsUrl.searchParams.set("username", username);
  if (passkey) {
    registrationOptionsUrl.searchParams.set("passkey", true);
  }
  const registrationOptionsRequest = new Request(registrationOptionsUrl, {
    method: "POST",
  });
  registrationOptionsRequest.headers.set("Accept", "application/json");
  const registrationOptionsResponse = await fetch(registrationOptionsRequest);
  if (registrationOptionsResponse.status != 200) {
    console.error(registrationOptionsResponse);
    if (
      registrationOptionsResponse.headers.get("content-type") ==
        "application/json"
    ) {
      const json = await registrationOptionsResponse.json();
      setStatus("Request failed: " + json.message);
    } else {
      setStatus("Request failed");
    }
    return;
  }
  const registrationOptions = await registrationOptionsResponse.json();
  const options = parseWebAuthnObject(registrationOptions.options);
  const authenticatingData = registrationOptions.authenticatingData;
  return {
    options,
    authenticatingData,
  };
}

/**
 * @param {string} username
 * @param {AuthenticatorAssertionResponse} response
 * @returns
 */
async function sendRegistration(username, response, transports) {
  const json = {
    username: username,
    response: stringifyWebAuthnObject(response),
    transports,
  };
  const registrationUrl = new URL(
    "/registration/submit",
    document.location,
  );
  const registrationRequest = new Request(registrationUrl, {
    method: "POST",
    body: JSON.stringify(json),
    headers: new Headers([
      ["content-type", "application/json"],
    ]),
  });
  const registrationResponse = await fetch(registrationRequest);
  if (registrationResponse.status != 200) {
    console.error(registrationResponse);
    if (
      registrationResponse.headers.get("content-type") == "application/json"
    ) {
      const json = await registrationResponse.json();
      setStatus("Request failed: " + json.message);
    } else {
      setStatus("Request failed");
    }
    return false;
  }
  return true;
}

document.querySelector("#register").addEventListener("click", async () => {
  setStatus("");
  const usernameField = document.getElementById("username");
  const username = usernameField.value;
  if (!username || username == "") {
    setStatus("Missing username");
    return;
  }
  /** @type {HTMLInputElement} */
  const passkeyField = document.getElementById("passkey");
  const passkey = passkeyField.checked;
  const opts = await getOptions(username, passkey);
  if (!opts) {
    return;
  }
  const { options } = opts;
  try {
    const credential = await navigator.credentials.create({
      publicKey: options,
    });
    console.log(credential);
    if (credential && credential.type == "public-key") {
      /** @type {PublicKeyCredential} */
      const publicKeyCredential = credential;
      /** @type {AuthenticatorAttestationResponse} */
      const response = publicKeyCredential.response;
      const transports = publicKeyCredential.response.getTransports &&
        publicKeyCredential.response.getTransports();
      const status = await sendRegistration(
        username,
        {
          attestationObject: response.attestationObject,
          clientDataJSON: response.clientDataJSON,
        },
        transports,
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
});
