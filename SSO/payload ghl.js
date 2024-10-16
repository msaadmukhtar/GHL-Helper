//Copied from original code  https://github.com/GoHighLevel/ghl-marketplace-app-template/blob/9df54d0135e78e744705507e047663859668f263/src/ui/src/ghl/index.js

async function getUserData() {
    const key = await new Promise((resolve) => {
        window.parent.postMessage({ message: "REQUEST_USER_DATA" }, "*");
        window.addEventListener("message", ({ data }) => {
            if (data.message === "REQUEST_USER_DATA_RESPONSE") {
                resolve(data.payload)
            }
        });
    });
    const res = await fetch('/decrypt-sso', {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ key })
    });
    const data = await res.json()
    return data
}




