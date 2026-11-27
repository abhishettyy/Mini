const el = id => document.getElementById(id);
const workspace = document.querySelector('.workspace');
const request = 'Find my CN report PDF and submit it using the form link in my email.';
const report = 'CN_Report.pdf';
const destination = 'forms.northbridge.example/cn-lab';
const student = 'Asha Rao';
const studentId = 'CS24-1187';
const sections = { b1: 'B1 · Tuesday, 10:00 AM', b2: 'B2 · Thursday, 2:00 PM' };
const clarificationStep = 6;
const approvalStep = 8;
const submitStep = 10;
const completeStep = 11;
const rejectedStep = 12;
const closingStep = 13;

const chapters = [
  { name: 'Request', short: 'Phone to laptop', summary: 'Asha asks from her phone. NectarLink hands the request to the paired laptop.', start: 0 },
  { name: 'Prepare', short: 'Files, inbox and form', summary: 'Mini finds the course report, reads the coordinator’s email, follows its link and stages the form.', start: 2 },
  { name: 'Review', short: 'Your decision', summary: 'Asha chooses her lab section. The phone shows the exact form and attachment for her approval.', start: 6 },
  { name: 'Receipt', short: 'Back to the phone', summary: 'After the laptop verifies the approval, the portal accepts the report and returns a receipt.', start: 10 }
];

function chapterFor(index) {
  return chapters.findLastIndex(chapter => chapter.start <= (index === rejectedStep ? approvalStep : index));
}

let section = '';
let approval = null;
let mode = 'ready';
let scriptedResponse = false;

function button(action, text, style = 'subtle') {
  return '<button type="button" class="button ' + style + '" data-action="' + action + '">' + text + '</button>';
}

function phone(status, content, extra = '') {
  return '<section class="phone ' + extra + '"><div class="phone-head"><span>Mini companion</span><span>' +
    status + '</span></div>' + content + '</section>';
}

function laptop(app, location, content) {
  return '<div class="laptop"><div class="laptop-screen"><section class="app"><div class="app-bar"><span>' +
    app + '</span><span class="app-url">' + location + '</span></div><div class="app-body">' +
    content + '</div></section></div><div class="laptop-base" aria-hidden="true"></div></div>';
}

function voiceRequest(sending = false) {
  const bars = Array.from({ length: 26 }, (_, i) => {
    const height = 7 + Math.abs(Math.sin(i * 1.93)) * 23;
    return '<i style="--h:' + height + 'px;--delay:' + (-i * .043) + 's"></i>';
  }).join('');
  const handset = phone(sending ? 'Sending' : 'Voice request',
    '<div class="voice-disc" aria-hidden="true"><i class="mini-mark"></i></div>' +
    '<div class="wave" aria-hidden="true">' + bars + '</div><p class="bubble">“' + request + '”</p>', 'opening-phone');
  return sending ? handset : '<div class="opening-shot"><cn-report></cn-report>' + handset + '</div>';
}

function email() {
  return '<p><strong>Computer Networks Lab · Report submission</strong></p>' +
    '<p>From Lab Coordinator &lt;cn-lab@northbridge.example&gt;</p>' +
    '<p>Please submit your CN report as a PDF. Enter your name, student ID, and lab section in the form.</p>' +
    '<p><strong>Submission link</strong> · ' + destination + '</p>';
}

function submissionValues() {
  return [
    ['Name', student],
    ['Student ID', studentId],
    ['Course', 'Computer Networks'],
    ['Lab section', sections[section] || 'Needs your input']
  ];
}

function details(rows) {
  return '<dl class="details-list">' + rows.map(([name, value]) =>
    '<div><dt>' + name + '</dt><dd>' + value + '</dd></div>').join('') + '</dl>';
}

function portal(attachmentState, animated = false) {
  const values = submissionValues().map(([name, value], index) => {
    const empty = index === 3 && !section;
    return '<div class="field' + (empty ? ' empty' : '') + '"><dt>' + name + '</dt><dd' +
      (animated ? ' class="reveal" style="--i:' + (2 * index + 1) + '"' : '') + '>' + value + '</dd></div>';
  }).join('');
  const attaching = attachmentState === 'uploading';
  const attachment = attachmentState ?
    '<div class="attachment ' + (attaching ? 'uploading' : '') + '"><span class="file-icon">PDF</span><strong>' +
    report + '</strong><span class="matched">' + (attaching ? 'Uploading' : 'Attached') + '</span></div>' :
    '<div class="attachment"><span class="file-icon">PDF</span> Choose report PDF</div>';
  return laptop('Browser · Northbridge University', destination,
    '<p class="eyebrow">COMPUTER NETWORKS LAB</p><h3>Report submission</h3><dl class="field-set">' + values + '</dl>' + attachment);
}

function checks(items) {
  return '<ul class="checks">' + items.map((item, i) =>
    '<li class="reveal" style="--i:' + (i * 4) + '">' + item + '</li>').join('') + '</ul>';
}

const scenes = [
  {
    label: 'Request', actor: 'Mini companion', state: 'Paired with laptop', title: '“Submit my CN report.”',
    caption: 'The PDF is on Asha’s laptop. The form is in her inbox. She starts the whole submission from her phone.',
    event: 'Phone and laptop paired through NectarLink.',
    render: () => voiceRequest()
  },
  {
    label: 'Handoff', actor: 'NectarLink → Mini Daemon', state: 'Transferring', title: 'Your laptop takes over.',
    caption: 'The paired devices pass the request. OpenClaw plans the file search, inbox search, and browser steps.',
    event: 'NectarLink delivered the request. Mini Daemon opened task CN–027 and passed it to OpenClaw.',
    duration: 4100,
    render: () => '<div class="handoff">' + voiceRequest(true) + '<div class="signal" aria-hidden="true"><i></i></div>' +
      laptop('Mini Daemon', 'NectarLink · Connected',
        '<div class="boot"><h3>OpenClaw task plan</h3><p>Find the report → Locate the form link → Prepare submission</p><p><strong>Task CN–027</strong> · Approved workspace</p></div>') + '</div>'
  },
  {
    label: 'Find PDF', actor: 'Filesystem MCP', state: 'Searching files', title: 'Find the right PDF.',
    caption: 'Mini searches the approved coursework folder and finds the Computer Networks report.',
    event: 'L0 filesystem read allowed. Mini found CN_Report.pdf in Coursework / CN.',
    duration: 5100,
    render: () => '<div class="device-shot">' + laptop('Files', 'Coursework / CN',
      '<div class="search">Search files &nbsp; <strong>CN report PDF</strong></div>' +
      '<div class="file-row reveal" style="--i:3"><span class="file-icon">PDF</span><div><strong>' + report +
      '</strong><small>Coursework / CN · Report PDF</small></div>' + button('report', 'Preview') + '</div>' +
      '<div class="ghost-row">CN_Notes.txt · Text document</div>') +
      '<div class="floating-file" aria-hidden="true"><cn-report></cn-report><span><strong>' + report + '</strong><small>Matched in Coursework / CN</small></span></div></div>'
  },
  {
    label: 'Find email', actor: 'Gmail MCP', state: 'Searching inbox', title: 'Find the form in email.',
    caption: 'Mini matches the lab coordinator’s message and finds the submission link inside it.',
    event: 'L0 inbox read allowed. Gmail MCP found the lab coordinator’s message and extracted the form URL.',
    duration: 6300,
    render: () => laptop('Mail · Student inbox', 'Computer Networks',
      '<div class="search">Search inbox &nbsp; <strong>CN report submission form</strong></div>' +
      '<div class="mail-row reveal" style="--i:3"><span class="file-icon">MAIL</span><div><strong>Computer Networks Lab · Report submission</strong>' +
      '<small>Lab Coordinator · Includes a submission link</small></div>' + button('email', 'Read email') + '</div>' +
      '<div class="email-link reveal" style="--i:8"><strong>Submission link</strong><span>' + destination +
      '</span>' + button('form', 'Open form', 'primary') + '</div>')
  },
  {
    label: 'Fill form', actor: 'Browser MCP', state: 'Filling form', title: 'Fill what Mini knows.',
    caption: 'The browser opens the form and fills your name, student ID, and course from your saved details.',
    event: 'Browser opened the form from the email and staged three fields from the sample student profile.',
    duration: 5300,
    render: () => portal('', true)
  },
  {
    label: 'Upload PDF', actor: 'Browser MCP', state: 'Uploading PDF', title: 'Attach the report.',
    caption: 'Mini uploads the PDF it found earlier. The form still needs your lab section.',
    event: 'Browser staged CN_Report.pdf in the mock form. The lab section remained unfilled.',
    duration: 5100,
    render: () => '<div class="device-shot">' + portal('uploading') +
      '<div class="file-flight" aria-hidden="true"><cn-report></cn-report></div></div>'
  },
  {
    label: 'Clarify', actor: 'Mini companion', state: 'Waiting for your answer', title: 'Mini asks when it’s unsure.',
    caption: 'The form lists two lab sections. Choose yours on the phone to continue.',
    event: 'Mini paused and requested the missing lab section through the phone.',
    render: () => phone('Quick question',
      '<h3>Which lab section are you in?</h3><p>The form lists two sections for your course.</p>' +
      button('b1', sections.b1, 'subtle choice') + button('b2', sections.b2, 'subtle choice'), 'return-phone')
  },
  {
    label: 'Prepare', actor: 'Browser MCP → Policy gate', state: 'Staged for review', title: 'Finish preparing the form.',
    caption: 'Mini enters the section you picked and stages the exact form and attachment for review.',
    event: () => 'User selected ' + sections[section] + '. Policy classified submission as L2 and staged the review snapshot.',
    duration: 4300,
    render: () => portal('attached')
  },
  {
    label: 'Approve', actor: 'Mini companion', state: 'Waiting for approval', title: 'The final tap is yours.',
    caption: 'Review the destination, the exact field values, and the attached report before approving the submission.',
    event: 'Approval contract CN–027 delivered to the phone. Browser submission paused.',
    render: () => phone('Final approval',
      '<h3>Submit your CN report?</h3>' + details([...submissionValues(), ['Attachment', report], ['Destination', destination]]) +
      '<div class="phone-actions">' + button('approve', 'Approve & submit', 'primary') + button('reject', 'Reject') + '</div>', 'return-phone')
  },
  {
    label: 'Verify', actor: 'Policy gate', state: 'Verifying approval', title: 'Check the approval.',
    caption: 'The laptop checks that the destination, fields, and PDF match what you approved.',
    event: 'User approved the staged form. The independent policy gate checked the approved snapshot.',
    duration: 4400,
    render: () => laptop('Mini Policy Gate', 'CN–027 · One-time approval',
      '<h3>Checking the approved submission</h3>' + checks([
        'Portal destination matches approval',
        'Form fields and PDF match the reviewed snapshot',
        'One-time approval permits submission to the mock portal'
      ]))
  },
  {
    label: 'Submit', actor: 'Browser MCP', state: 'Submitting in demo', title: 'Send the approved form.',
    caption: 'The browser submits the completed form and PDF to the simulated university portal.',
    event: 'Policy consumed the one-time demo approval. Browser submitted the approved form to the mock portal.',
    duration: 3200,
    render: () => laptop('Browser · Northbridge University', destination,
      '<h3>Submitting report</h3><p>' + student + ' · ' + studentId + '</p><p>' + sections[section] +
      ' · ' + report + '</p><div class="submit-track" aria-hidden="true"><i></i></div>')
  },
  {
    label: 'Receipt', actor: 'Mini companion', state: 'Submitted in demo', title: 'It’s submitted.',
    caption: 'The portal accepts the report. Mini returns the receipt to your phone.',
    event: 'Mock portal accepted the form and returned receipt CN–4821 to the phone.',
    render: () => phone('Submission receipt',
      '<div class="receipt-slot"><div class="receipt-paper"><span class="receipt" aria-hidden="true">✓</span><h3>CN report submitted</h3><p>' + report +
      '<br>' + sections[section] + '</p><p class="receipt-code">RECEIPT CN–4821</p></div></div>', 'return-phone')
  },

  {
    label: 'Rejected', actor: 'Mini companion', state: 'Submission declined', title: 'Your draft stays ready.',
    caption: 'Mini keeps the completed form available for review.',
    event: 'User rejected the final action. Policy blocked submission and retained the draft.',
    render: () => phone('Submission declined',
      '<div class="stamp waiting">Draft saved</div><h3>CN report ready to review</h3>' +
      details([['Lab section', sections[section]], ['Attachment', report]]) +
      '<div class="phone-actions">' + button('review-draft', 'Review draft') + '</div>', 'return-phone')
  },
  {
    label: 'Mini', actor: 'CN REPORT SUBMISSION', state: 'Film complete', title: 'From request to receipt.',
    caption: 'A phone request, a laptop workflow, and approval in your hands.',
    event: 'The scripted product film completed.',
    render: () => '<div class="brand-end"><i class="mini-mark" aria-hidden="true"></i><strong>mini</strong><div class="end-proof">✓ &nbsp; CN–4821 · Submitted in demo</div></div>'
  }
];

let step = 0;
let paused = false;
let timer;
let progressAnimation;
let remaining = 0;
let lastStarted = 0;
let runningPace = 1;
let log = [];

function sceneDuration() {
  if (mode !== 'ready' && step === 0) return 3900;
  if (mode === 'film') {
    if (scriptedResponse) return 750;
    if (step === completeStep) return 3900;
    if (step === clarificationStep) return 3600;
    if (step === approvalStep) return 5500;
  }
  return scenes[step].duration || 0;
}

function currentSnapshot() {
  return JSON.stringify({ destination, values: submissionValues(), report });
}

function renderRail() {
  if (!el('rail').childElementCount) {
    el('rail').innerHTML = chapters.map((chapter, i) =>
      '<button type="button" data-action="chapter" data-chapter="' + i + '" aria-haspopup="dialog"><span class="chapter-no">0' +
      (i + 1) + '</span><span><strong>' + chapter.name + '</strong><small>' + chapter.short + '</small></span></button>').join('');
  }
  for (const control of el('rail').children) {
    if (Number(control.dataset.chapter) === chapterFor(step)) control.setAttribute('aria-current', 'step');
    else control.removeAttribute('aria-current');
  }
}

function renderControls() {
  workspace.dataset.paused = paused || el('details').open;
  if (sceneDuration()) {
    el('controls').innerHTML = button('pause', paused ? 'Resume' : 'Pause') + button('next', 'Next scene');
  } else if (step >= completeStep) {
    el('controls').innerHTML = button(mode === 'film' ? 'play' : 'restart-interactive', 'Replay');
  } else {
    el('controls').textContent = mode === 'ready' ? 'Silent product film · 4 chapters' : 'Choose on the phone to continue';
  }
}

function stopClock() {
  if (timer !== undefined) {
    clearTimeout(timer);
    remaining = Math.max(0, remaining - (performance.now() - lastStarted) * runningPace);
    timer = undefined;
  }
  progressAnimation?.cancel();
  progressAnimation = null;
  const duration = sceneDuration();
  el('progress').style.width = duration ? (1 - remaining / duration) * 100 + '%' : '0%';
}

function schedule() {
  stopClock();
  if (!sceneDuration() || paused || el('details').open) return;
  runningPace = Number(el('pace').value);
  const interval = remaining / runningPace;
  lastStarted = performance.now();
  if (!matchMedia('(prefers-reduced-motion: reduce)').matches) {
    progressAnimation = el('progress').animate([
      { width: el('progress').style.width }, { width: '100%' }
    ], { duration: interval, fill: 'forwards' });
  }
  timer = setTimeout(advance, interval);
}

function enter(next, focus = false) {
  stopClock();
  step = next;
  scriptedResponse = false;
  delete workspace.dataset.responding;
  if (step === 0) {
    log = [];
    paused = false;
    section = '';
    approval = null;
  }
  const scene = scenes[step];
  remaining = sceneDuration();
  const entry = typeof scene.event === 'function' ? scene.event() : scene.event;
  log.push({ step, entry });
  workspace.dataset.state = step === rejectedStep ? 'rejected' : step === completeStep || step === closingStep ? 'complete' :
    step === approvalStep || step === clarificationStep ? 'attention' : 'running';
  workspace.dataset.scene = scene.label.toLowerCase().replaceAll(' ', '-');
  workspace.dataset.mode = mode;
  workspace.toggleAttribute('data-still', paused);
  el('actor').textContent = scene.actor;
  if (step === 0) el('title').innerHTML = '“Submit my <em>CN report.”</em>';
  else el('title').textContent = scene.title;
  el('caption').textContent = scene.caption;
  if (mode === 'film' && step === clarificationStep) {
    el('caption').textContent = 'The form offers two lab sections. Mini asks Asha, who chooses Thursday’s lab on her phone.';
  } else if (mode === 'film' && step === approvalStep) {
    el('caption').textContent = 'Asha checks the destination, the completed fields and the PDF before she approves the submission.';
  }
  el('status').textContent = scene.state;
  el('mode').textContent = mode === 'film' ? 'Product film' : mode === 'interactive' ? 'Interactive walkthrough' : 'Phone request';
  el('opening-controls').innerHTML = mode === 'ready' ? button('play', 'Play the film', 'primary') +
    button('start', 'Try it yourself') : '';
  el('scene').innerHTML = scene.render();
  renderRail();
  renderControls();
  schedule();
  if (!paused && !matchMedia('(prefers-reduced-motion: reduce)').matches) {
    el('title').animate([{ opacity: 0, transform: 'translateY(13px)' }, { opacity: 1, transform: 'translateY(0)' }],
      { duration: 460, easing: 'cubic-bezier(.22,.8,.22,1)' });
  }
  if (focus || (mode === 'interactive' && (step === approvalStep || step === clarificationStep))) {
    const target = el('opening-controls').querySelector('.primary') ||
      el('scene').querySelector('.primary, .choice') || el('controls').querySelector('button');
    target?.focus({ preventScroll: true });
  }
}

function advance() {
  if (!sceneDuration()) return;
  if (mode === 'film' && (step === clarificationStep || step === approvalStep)) {
    const choosing = step === clarificationStep;
    if (!scriptedResponse) {
      stopClock();
      scriptedResponse = true;
      workspace.dataset.responding = choosing ? 'b2' : 'approve';
      el('status').textContent = choosing ? 'Sample user selects B2' : 'Sample user approves';
      remaining = sceneDuration();
      schedule();
      return;
    }
    if (choosing) section = 'b2';
    else approval = currentSnapshot();
  }
  if (step === completeStep) {
    enter(closingStep);
    return;
  }
  if (step + 1 === submitStep) {
    if (approval !== currentSnapshot()) return;
    approval = null;
  }
  enter(step + 1);
}

function inspect(title, content) {
  stopClock();
  el('details-title').textContent = title;
  el('details-content').innerHTML = content;
  el('details').showModal();
  workspace.dataset.paused = true;
}

function activity(entries) {
  return '<ol class="audit-list">' + entries.map(({ entry }) => '<li>' + entry + '</li>').join('') + '</ol>';
}

document.addEventListener('click', event => {
  const target = event.target.closest('button[data-action]');
  if (!target) return;
  const action = target.dataset.action;
  switch (action) {
    case 'play':
      mode = 'film';
      enter(0, true);
      break;
    case 'start':
    case 'restart-interactive':
      mode = 'interactive';
      enter(0, true);
      break;

    case 'reset':
      mode = 'ready';
      enter(0, true);
      break;
    case 'next':
      advance();
      (el('controls').querySelector('[data-action="next"]') || el('scene').querySelector('.primary, .choice') || el('controls').querySelector('button'))?.focus({preventScroll:true});
      break;
    case 'form':
      if (step === 3) {
        if (el('details').open) el('details').close();
        enter(4, true);
      }
      break;
    case 'b1':
    case 'b2':
      if (step === clarificationStep) {
        section = action;
        enter(7, true);
      }
      break;
    case 'approve':
      if (step === approvalStep) {
        approval = currentSnapshot();
        enter(9, true);
      }
      break;
    case 'reject': if (step === approvalStep) enter(rejectedStep, true); break;
    case 'pause':
      paused = !paused;
      renderControls();
      schedule();
      el('controls').querySelector('[data-action="pause"]').focus();
      break;
    case 'report':
      inspect(report, '<div class="document-preview"><cn-report></cn-report><div><h3>Computer Networks Lab</h3>' +
        '<p>' + student + ' · ' + studentId + '</p><p>TCP/IP packet analysis and round-trip latency measurements.</p></div></div>');
      break;
    case 'email':
      inspect('Email from the lab coordinator', email() + '<div class="inspect-row">' +
        button('form', 'Open submission form', 'primary') + '</div>');
      break;
    case 'review-draft':
      inspect('Staged form', details([...submissionValues(), ['Attachment', report], ['Destination', destination]]));
      break;
    case 'activity': inspect('Execution trace', activity(log)); break;
    case 'chapter': {
      const index = Number(target.dataset.chapter);
      const entries = log.filter(item => chapterFor(item.step) === index);
      inspect(chapters[index].name, '<p>' + chapters[index].summary + '</p>' + (entries.length ? activity(entries) : ''));
      break;
    }

  }
});

el('details').addEventListener('close', () => {
  workspace.dataset.paused = paused;
  schedule();
});
el('pace').addEventListener('change', schedule);
const fullscreen = el('fullscreen');
if (document.fullscreenEnabled) {
  fullscreen.hidden = false;
  fullscreen.addEventListener('click', async () => {
    try {
      if (document.fullscreenElement) await document.exitFullscreen();
      else await document.documentElement.requestFullscreen();
    } catch {
      fullscreen.textContent = 'Fullscreen unavailable';
    }
  });
  document.addEventListener('fullscreenchange', () => {
    fullscreen.textContent = document.fullscreenElement ? 'Exit fullscreen' : 'Fullscreen';
  });
}
if (location.hash === '#film') mode = 'film';
if (location.hash === '#interactive') mode = 'interactive';
enter(0);
