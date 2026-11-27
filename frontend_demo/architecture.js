'use strict';

const byId = id => document.getElementById(id);

const components = {
  phone: {
    title: 'Mobile Companion', layer: 'Phone · Android / Kotlin',
    text: 'The user gives a natural-language request, selects files from approved directories, or captures a paper document with the camera. The Human Input Handler brings an OTP, CAPTCHA, or ambiguous field back to the user.',
    route: 'Outputs: task intent, selected documents, and human input to the Mini Daemon via NectarLink.'
  },
  review: {
    title: 'Control & Approval UI', layer: 'Phone · Human authority',
    text: 'The Evidence Viewer shows the exact action, its destination, and the artifact under review. Depending on the tool, this can include a report preview, form values, a screenshot, an email draft, or a file or Git diff. The user can approve, reject, pause, or cancel.',
    route: 'The approval response returns through NectarLink to the laptop for independent verification.'
  },
  link: {
    title: 'NectarLink', layer: 'Connectivity · Device boundary',
    text: 'The Android and desktop integrations pair the devices and carry task messages, selected files, previews, and responses across an authenticated, encrypted connection. Mini supplies application-level task authorization.',
    route: 'Bidirectional transport between the companion and daemon, using the pairing modes NectarLink supports.'
  },
  daemon: {
    title: 'Mini Daemon', layer: 'Laptop · Task coordination',
    text: 'The daemon creates the task session, tracks its lifecycle, and passes the request to OpenClaw. It routes requests for human input or approval and reports progress and final results to the phone.',
    route: 'The task ID follows the plan, staged files, approval contract, and audit events.'
  },
  planner: {
    title: 'OpenClaw', layer: 'Laptop · AI planning',
    text: 'OpenClaw breaks the task into operations, orders their dependencies, and selects MCP capabilities. Each tool call is a proposal. An independent gate controls access to the laptop and external services.',
    route: 'Example: propose project search, document generation, browser form preparation, then submission.'
  },
  gate: {
    title: 'Independent Policy Enforcement Layer', layer: 'Laptop · Permission boundary',
    text: 'The gate checks every invocation against task scope, allowed operations, approved paths, and risk. It blocks protected credentials and system paths. Changes are prepared in an isolated task workspace, preserving originals and rollback information where supported.',
    route: 'Permitted reads and staged changes can proceed. Sensitive actions enter the approval flow. Forbidden actions terminate here.'
  },
  contract: {
    title: 'Approval Contract Manager', layer: 'Laptop · Exact-action authorization',
    text: 'The contract binds a task ID, action, exact parameters, destination, artifact ID and digest, risk level, expiry, and single-use nonce. The phone reviews the evidence. The laptop verifies the signed response, then independently checks current policy and the bound inputs again.',
    route: 'A changed artifact or destination, an expired or reused approval, or a revoked permission blocks execution.'
  },
  execute: {
    title: 'Scoped MCP execution', layer: 'Laptop · Tools & applications',
    text: 'A specialized server acts within the permissions granted for this task. A document tool writes a staged report. A browser tool can submit to the reviewed URL after authorization. The daemon routes the outcome and available evidence back to the phone.',
    route: 'Execution events go to the Glass-Box Monitor and audit logger.'
  },
  observe: {
    title: 'Glass-Box Monitor & Audit Logger', layer: 'Observability · Across the task',
    text: 'The monitor shows calls, file access, staged changes, pending approvals, blocked actions, and execution status. Pause, cancel, and emergency stop provide human control. The audit logger preserves the sequence of decisions from the request through its outcome.',
    route: 'The policy demo below shows both the operator controls and a task-scoped audit trace.'
  }
};

const submissionTrace = [
  ['phone', 'The student requests a lab report and shares a rubric from the phone.'],
  ['link', 'The paired connection carries the request and selected rubric to the laptop.'],
  ['daemon', 'The daemon opens a task session and hands the request to the orchestrator.'],
  ['planner', 'OpenClaw plans project search, report generation, form preparation, and final submission.'],
  ['gate', 'Each preparation call is checked. Permitted reads use the approved project, and the report is generated in isolated staging.'],
  ['execute', 'The scoped tools stage the report and prepare the portal form. The final submit is a separate proposal.'],
  ['gate', 'The gate classifies the proposed external submission as L2 and requests approval.'],
  ['contract', 'The contract binds the destination, form contents, report hash, expiry, and one-time nonce.'],
  ['review', 'The phone receives the contract and evidence over NectarLink. The student approves the reviewed submission.'],
  ['gate', 'The laptop verifies the response and rechecks scope, destination, parameters, artifact integrity, expiry, and nonce.'],
  ['execute', 'Browser MCP performs the exact authorized submission and returns the portal receipt through the daemon.'],
  ['observe', 'The recorded trace ties the user request, tool calls, contract, policy decisions, and receipt to one task.']
];
let traceIndex = -1;
let flowTimer;
let playingFlow = false;

function stopFlow() {
  clearTimeout(flowTimer);
  playingFlow = false;
  byId('trace-play').textContent = 'Play flow';
  byId('trace-play').setAttribute('aria-pressed', 'false');
}

function animatePanel(panel) {
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  panel.getAnimations().forEach(animation => animation.cancel());
  panel.animate([
    { opacity: .55, transform: 'translateY(5px)' },
    { opacity: 1, transform: 'translateY(0)' }
  ], { duration: 260, easing: 'ease-out' });
}

function playFlow() {
  traceIndex++;
  if (traceIndex >= submissionTrace.length) {
    traceIndex = submissionTrace.length - 1;
    stopFlow();
    return;
  }
  inspectNode(submissionTrace[traceIndex][0]);
  flowTimer = setTimeout(playFlow, 3700);
}

function inspectNode(key) {
  const item = components[key];
  document.querySelectorAll('[data-node]').forEach(node => node.setAttribute('aria-pressed', String(node.dataset.node === key)));
  byId('inspect-label').textContent = item.layer;
  byId('inspect-title').textContent = item.title;
  document.querySelector('.system-board').dataset.selected = key;
  document.querySelector('.system-board').toggleAttribute('data-tracing', traceIndex >= 0);
  document.querySelector('.inspect-symbol').dataset.component = key;
  byId('inspect-text').textContent = traceIndex < 0 ? item.text : submissionTrace[traceIndex][1];
  byId('inspect-route').textContent = item.route;
  byId('trace-controls').hidden = traceIndex < 0;
  byId('trace-start').textContent = traceIndex < 0 ? 'Trace a submission' : 'Exit trace';
  byId('trace-count').textContent = (traceIndex + 1) + ' of ' + submissionTrace.length;
  byId('trace-back').disabled = traceIndex <= 0;
  byId('trace-next').textContent = traceIndex === submissionTrace.length - 1 ? 'Finish trace' : 'Next step';
  animatePanel(byId('inspect-title'));
}

document.querySelectorAll('[data-node]').forEach(node => node.addEventListener('click', () => {
  stopFlow();
  traceIndex = -1;
  inspectNode(node.dataset.node);
}));
byId('trace-start').onclick = () => {
  stopFlow();
  traceIndex = traceIndex < 0 ? 0 : -1;
  inspectNode('phone');
};
byId('trace-play').onclick = () => {
  if (playingFlow) {
    stopFlow();
    return;
  }
  playingFlow = true;
  byId('trace-play').textContent = 'Pause flow';
  byId('trace-play').setAttribute('aria-pressed', 'true');
  if (traceIndex >= submissionTrace.length - 1) traceIndex = -1;
  playFlow();
};
byId('trace-back').onclick = () => {
  stopFlow();
  inspectNode(submissionTrace[--traceIndex][0]);
};
byId('trace-next').onclick = () => {
  stopFlow();
  traceIndex++;
  if (traceIndex === submissionTrace.length) {
    traceIndex = -1;
    byId('trace-start').focus();
    inspectNode('observe');
  } else {
    inspectNode(submissionTrace[traceIndex][0]);
  }
};
inspectNode('phone');

const tools = [
  ['Filesystem', 'Restrict reads and writes to approved directories. Stage modifications in a task-specific workspace.', 'Read Coursework/CN/CN_Report.pdf for the current task.', 'Show the exact path, a before/after diff for modifications, or the affected paths and impact for deletion.'],
  ['Search', 'Locate relevant projects, source files, and documents within the task’s permitted scope.', 'Find project measurements that match the rubric shared from the phone.', 'Show the query, searched directories, and matching source paths.'],
  ['Document', 'Use python-docx and docxtpl to populate templates and prepare DOCX or PDF reports in staging.', 'Generate a lab report from the selected rubric and project results.', 'Show the document preview, artifact version, and cryptographic digest.'],
  ['Browser', 'Use Playwright to navigate pages, fill forms, and collect screenshots. Evaluate an external submission as a separate operation.', 'Populate the university portal with approved fields and a staged report.', 'Show the destination URL, exact field values, attachment, and supporting screenshot.'],
  ['Gmail', 'Find relevant conversations, prepare drafts, and send messages once policy and the required approval permit it.', 'Find the lab coordinator’s message containing the submission form link.', 'For sending, show recipients, subject, body, and attachments.'],
  ['Git', 'Inspect a repository, produce diffs, and prepare commits. Evaluate publication to a remote before pushing.', 'Propose pushing reviewed commits to a specific branch and remote.', 'Show staged diffs and commit message for a commit, or the remote, branch, and commits for a push.']
];
tools.forEach(([name], index) => {
  const control = document.createElement('button');
  control.type = 'button';
  control.textContent = name + ' MCP';
  const icon = document.createElement('i');
  icon.className = 'tool-icon';
  icon.dataset.tool = name;
  icon.setAttribute('aria-hidden', 'true');
  control.prepend(icon);
  control.onclick = () => selectTool(index);
  byId('tool-menu').append(control);
});
function selectTool(index) {
  const [name, purpose, example, evidence] = tools[index];
  Array.from(byId('tool-menu').children).forEach((button, i) => button.setAttribute('aria-pressed', String(i === index)));
  byId('tool-name').textContent = name + ' MCP';
  byId('tool-emblem').dataset.tool = name;
  byId('tool-purpose').textContent = purpose;
  byId('tool-example').textContent = example;
  byId('tool-evidence').textContent = evidence;
  animatePanel(document.querySelector('.tool-detail'));
}
selectTool(0);

// All operations below are local fixtures. No filesystem, mail, browser or remote service is invoked.
const cases = {
  submit: { risk: 'L2', title: 'Sensitive external action', action: 'Browser · Submit form', target: 'forms.northbridge.example/cn-lab', description: 'Review the exact form and attachment on the phone. Then let the laptop revalidate the approved action.' },
  read: { risk: 'L0', title: 'Read-only operation', action: 'Filesystem · Read report', target: 'Coursework/CN/CN_Report.pdf', description: 'The selected report is inside the approved coursework directory. A scoped read can run automatically.' },
  stage: { risk: 'L1', title: 'Reversible operation', action: 'Document · Generate report', target: 'task workspace / CN_Report.docx', description: 'Generate a report in the isolated staging workspace. The original project files stay available for comparison and rollback.' },
  delete: { risk: 'L3', title: 'Highly destructive action', action: 'Filesystem · Delete folder', target: 'Coursework/CN/Archive', description: 'Review the exact path and affected contents. This sample requires the folder name as strong confirmation before explicit approval.' },
  deny: { risk: 'Denied', title: 'Protected path', action: 'Filesystem · Read credential file', target: 'project/.env', description: 'The path is excluded from the task’s permissions. Even a read-only request can be denied.' }
};
const digests = [
  'c79afb517cbfe3c4187371edba54312161b0b1b3e223db6b4f0ba36dd9f1b675',
  '2dad73bb57c20927544a68c2bd84ac0e90020f6f981d840f5d8ee42acddb73ca'
];
const manifestDigest = '1f00ca1ea84e167cd9a6e5176db7561b7aaff6b985ef54cd5424e09cabba1190';
let taskNumber = 0;
let task;
const scenario = byId('scenario');

function record(component, detail, kind = 'info') {
  const row = document.createElement('li');
  const time = document.createElement('time');
  const now = new Date();
  time.dateTime = now.toISOString();
  time.textContent = now.toLocaleTimeString('en-GB', {hour12:false});
  const message = document.createElement('span');
  const name = document.createElement('b');
  name.textContent = component + ' · ';
  message.append(name, detail);
  row.dataset.kind = kind;
  row.append(time, message);
  byId('events').append(row);
  byId('events').scrollTop = byId('events').scrollHeight;
}

function snapshot() {
  const isDeletion = task.key === 'delete';
  const item = cases[task.key];
  return {
    taskId: task.id, risk: item.risk, action: item.action, target: item.target,
    parameters: isDeletion ? 'Delete Archive and its one report' : 'Asha Rao · CS24-1187 · Computer Networks · B2',
    artifact: isDeletion ? 'Archive manifest · v1' : 'CN_Report.pdf · v' + (task.version + 1),
    hash: isDeletion ? manifestDigest : digests[task.version]
  };
}

function setPhase(phase, message) {
  task.phase = phase;
  task.message = message;
  renderTask();
}

function newTask() {
  const id = 'CN–' + String(++taskNumber).padStart(3, '0');
  task = { id, key: scenario.value, phase: 'Ready', message: 'The tool call is ready for the independent policy gate.', version: 0, contract: null, permitted: true, paused: false };
  byId('events').replaceChildren();
  record('Daemon', id + ' created with an isolated coursework workspace.');
  record('OpenClaw', cases[task.key].action + ' proposed.');
  renderTask();
}

function evaluate() {
  const item = cases[task.key];
  record('Policy gate', 'Evaluating ' + item.action + ' for ' + item.target + '.');
  if (task.key === 'deny') {
    record('Policy gate', 'Denied access to the protected path.', 'block');
    setPhase('Blocked', 'Policy denied the tool call before execution.');
  } else if (item.risk === 'L0' || item.risk === 'L1') {
    const result = item.risk === 'L0' ? 'Read the permitted report.' : 'Created a staged document in this task’s workspace.';
    record('Policy gate', item.risk + ' permitted within task scope.');
    record('Tool execution', result, 'done');
    setPhase('Completed', result);
  } else {
    const bytes = crypto.getRandomValues(new Uint32Array(2));
    task.contract = {
      bound: snapshot(),
      nonce: Array.from(bytes, n => n.toString(16).padStart(8, '0')).join(''),
      expiry: Date.now() + 120000,
      approved: false,
      consumed: false
    };
    record('Contract manager', 'One-time approval requested. Evidence and contract sent to the phone.');
    setPhase('Phone review', 'Review this sample contract. The proposed system authenticates the phone response with a cryptographic signature.');
  }
}

function approve() {
  if (task.key === 'delete' && byId('confirm-folder').value !== 'Archive') {
    byId('confirm-folder').setCustomValidity('Type Archive to confirm this folder.');
    byId('confirm-folder').reportValidity();
    return;
  }
  task.contract.approved = true;
  record('Phone', 'User authorized the reviewed operation.');
  setPhase('Approved', 'The laptop must independently recheck this approval and current permissions before execution.');
}

function revalidate() {
  const contract = task.contract;
  let failure = '';
  if (contract.consumed) failure = 'This nonce was already consumed.';
  else if (!contract.approved) failure = 'The request has no approval.';
  else if (Date.now() >= contract.expiry) failure = 'This contract expired.';
  else if (JSON.stringify(contract.bound) !== JSON.stringify(snapshot())) failure = 'The current artifact differs from the reviewed version.';
  else if (!task.permitted) failure = 'Current task policy no longer permits this action.';
  if (failure) {
    record('Policy gate', failure + ' Execution blocked.', 'block');
    setPhase('Blocked', failure + ' A new permitted request requires a fresh review.');
    return;
  }
  contract.consumed = true;
  record('Policy gate', 'Task, action, target, fields, digest, expiry, nonce, and current scope checked.');
  record('Tool execution', task.key === 'submit' ? 'Mock portal returned receipt CN–4821.' : 'Simulated deletion of the reviewed folder.', 'done');
  setPhase('Completed', 'The approved operation ran once in this simulation.');
}

function action(label, handler, primary = false) {
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = label;
  if (primary) button.className = 'primary';
  button.disabled = task.paused;
  button.onclick = handler;
  byId('policy-actions').append(button);
}

function contractFields(rows) {
  const list = document.createElement('dl');
  rows.forEach(([key, value]) => {
    const row = document.createElement('div');
    const label = document.createElement('dt');
    const detail = document.createElement('dd');
    label.textContent = key;
    detail.textContent = value;
    row.append(label, detail);
    list.append(row);
  });
  return list;
}

function showContract(section) {
  const c = task.contract;
  const meta = document.createElement('details');
  meta.className = 'contract-meta';
  const summary = document.createElement('summary');
  summary.textContent = 'Inspect contract details';
  meta.append(summary, contractFields([
    ['Task / risk', c.bound.taskId + ' · ' + c.bound.risk],
    ['SHA-256', c.bound.hash], ['Nonce', c.nonce], ['Expires', new Date(c.expiry).toLocaleTimeString()]
  ]));
  section.append(contractFields([
    ['Operation', c.bound.action], ['Target', c.bound.target],
    ['Parameters', c.bound.parameters], ['Artifact', c.bound.artifact]
  ]), meta);
}

function renderTask() {
  const item = cases[task.key];
  byId('risk').textContent = item.risk;
  byId('case-title').textContent = item.title;
  byId('case-description').textContent = item.description;
  const decision = byId('decision');
  decision.replaceChildren();
  const message = document.createElement('p');
  message.textContent = task.message;
  decision.append(message);
  if (task.contract) showContract(decision);
  byId('policy-actions').replaceChildren();
  byId('monitor-status').textContent = task.paused ? 'Paused' : task.phase;
  byId('monitor-status').dataset.phase = task.phase;
  const active = ['Ready', 'Phone review', 'Approved'].includes(task.phase);
  byId('hold').disabled = !active;
  byId('hold').textContent = task.paused ? 'Resume' : 'Pause';
  byId('cancel').disabled = !active;
  byId('kill').disabled = !active;
  if (task.phase === 'Ready') {
    action('Evaluate request', evaluate, true);
  } else if (task.phase === 'Phone review') {
    if (task.key === 'delete') {
      const label = document.createElement('label');
      label.htmlFor = 'confirm-folder';
      label.textContent = 'Type Archive to confirm the affected folder';
      const input = document.createElement('input');
      input.id = 'confirm-folder';
      input.autocomplete = 'off';
      input.disabled = task.paused;
      input.oninput = () => input.setCustomValidity('');
      decision.append(label, input);
    }
    action('Approve exact action', approve, true);
    action('Reject', () => {
      record('Phone', 'Rejected. Staged evidence retained.', 'block');
      setPhase('Rejected', 'The proposed operation was blocked. Its staged evidence is available for review.');
    });
  } else if (task.phase === 'Approved') {
    action('Revalidate & execute', revalidate, true);
    if (task.key === 'submit' && task.version === 0) {
      action('Change staged PDF', () => {
        task.version = 1;
        record('Workspace', 'Staged PDF changed to v2 after approval.');
        setPhase('Approved', 'Current PDF is v2. The displayed contract still binds the reviewed v1.');
      });
    }
    if (task.permitted) action('Revoke permission', () => {
      task.permitted = false;
      record('Policy gate', 'Workspace permission revoked after approval.');
      setPhase('Approved', 'Current policy denies the approved action. Revalidate to see the result.');
    });
  } else {
    if (task.phase === 'Blocked' && task.contract && !task.contract.consumed && task.permitted) {
      action('Request fresh review', evaluate, true);
    }
    if (task.phase === 'Completed' && task.contract?.consumed) action('Try approval again', revalidate);
    action('Start new task', newTask, true);
  }
}

scenario.onchange = newTask;
byId('hold').onclick = () => {
  task.paused = !task.paused;
  record('Monitor', task.paused ? 'Paused task execution.' : 'Resumed task execution.');
  renderTask();
};
function interrupt(phase, message) {
  task.paused = false;
  if (task.contract) task.contract.approved = false;
  record('Monitor', message, 'block');
  setPhase(phase, message);
}
byId('cancel').onclick = () => interrupt('Cancelled', 'Task cancelled. Pending work stopped.');
byId('kill').onclick = () => interrupt('Stopped', 'Emergency stop applied. Execution halted and pending authorization invalidated.');
newTask();

document.addEventListener('visibilitychange', () => {
  if (document.hidden) stopFlow();
});




// Entrance motion is applied only to sections outside the initial viewport.
const motionPreference = matchMedia('(prefers-reduced-motion: reduce)');
if (!motionPreference.matches) {
  const entrances = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (!entry.isIntersecting) return;
      entry.target.classList.add('arrived');
      entrances.unobserve(entry.target);
    });
  }, {threshold: .06});
  document.querySelectorAll('.section, .feature-demo').forEach(section => {
    if (section.getBoundingClientRect().top > innerHeight) {
      section.classList.add('entrance');
      entrances.observe(section);
    }
  });
}
const navigation = [...document.querySelectorAll('.mast nav a')];
const sections = navigation.map(link => document.querySelector(link.hash));
function markNavigation() {
  const current = sections.filter(section => section.getBoundingClientRect().top < innerHeight * .45).at(-1);
  navigation.forEach(link => {
    if (current && link.hash === '#' + current.id) link.setAttribute('aria-current', 'location');
    else link.removeAttribute('aria-current');
  });
}
const navObserver = new IntersectionObserver(markNavigation, {rootMargin:'-15% 0px -45% 0px', threshold:0});
sections.forEach(section => navObserver.observe(section));
window.addEventListener('scroll', markNavigation, {passive:true});

