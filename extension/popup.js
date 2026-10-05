const box = document.getElementById('enabled');
const status = document.getElementById('status');

async function refresh() {
  const s = await chrome.runtime.sendMessage({ type: 'status' });
  box.checked = s.enabled;
  status.textContent = !s.enabled
    ? 'Disabled: agents cannot connect.'
    : s.connectedPorts.length
      ? `Connected to agent on port ${s.connectedPorts.join(', ')}.`
      : 'Idle: no agent is using the bridge right now.';
}

box.addEventListener('change', async () => {
  await chrome.runtime.sendMessage({ type: 'setEnabled', enabled: box.checked });
  refresh();
});

refresh();
