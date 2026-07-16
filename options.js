chrome.storage.local.get("vtApiKey", ({ vtApiKey }) => {
  if (vtApiKey) document.getElementById("vtKey").value = vtApiKey;
});

document.getElementById("save").addEventListener("click", () => {
  const key = document.getElementById("vtKey").value.trim();
  chrome.storage.local.set({ vtApiKey: key }, () => {
    document.getElementById("status").textContent = "Saved.";
    setTimeout(() => (document.getElementById("status").textContent = ""), 1500);
  });
});
