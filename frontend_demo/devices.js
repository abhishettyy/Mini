'use strict';

// Draw both devices in one coordinate system so the packet follows the link between them.
(() => {
  const canvas = document.getElementById('devices');
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const moments = [
    { phone: 'Task sent', note: 'Find my CN report', action: 'Request delivered', laptop: 'Task received', file: 'CN report submission', stage: 'Planning tool calls', direction: 'Phone to laptop' },
    { phone: 'In progress', note: 'Preparing the form', action: 'View progress', laptop: 'Staging workspace', file: 'CN_Report.pdf', stage: 'Form prepared', direction: 'Local preparation' },
    { phone: 'Review request', note: 'Submit CN report?', action: 'Review submission', laptop: 'Approval pending', file: 'CN_Report.pdf', stage: 'Waiting for phone', direction: 'Laptop to phone' }
  ];
  let current = 0;
  let visible = false;
  let frame = 0;
  let transitionStart = -1000;
  const pointer = {x:0,y:0};
  const tilt = {x:0,y:0};

  function box(x, y, w, h, r, fill, stroke) {
    ctx.beginPath();
    ctx.roundRect(x, y, w, h, r);
    ctx.fillStyle = fill;
    ctx.fill();
    if (stroke) {
      ctx.strokeStyle = stroke;
      ctx.lineWidth = 1;
      ctx.stroke();
    }
  }
  function type(str, x, y, size, color, weight = 500, family = '"DM Sans", Arial') {
    ctx.fillStyle = color;
    ctx.font = weight + ' ' + size + 'px ' + family;
    ctx.fillText(str, x, y);
  }
  function metal(x, y, w, h, colors) {
    const fill = ctx.createLinearGradient(x, y, x + w, y + h);
    colors.forEach((c, i) => fill.addColorStop(i / (colors.length - 1), c));
    return fill;
  }
  function shadow(x, y, w, h) {
    ctx.save();
    ctx.translate(x, y);
    ctx.scale(w, h);
    const glow = ctx.createRadialGradient(0, 0, 0, 0, 0, 1);
    glow.addColorStop(0, '#222b2c44');
    glow.addColorStop(1, '#222b2c00');
    ctx.fillStyle = glow;
    ctx.fillRect(-1,-1,2,2);
    ctx.restore();
  }
  function laptop(m, lift) {
    ctx.save();
    ctx.transform(1, -.16, -.72, .78, 319, 254);
    box(0, 5, 253, 98, 7, '#75807d');
    box(0, 0, 253, 98, 7, metal(0,0,253,98,['#939b98','#e9ebe5','#bdc4c0']), '#7d8984');
    box(10, 8, 233, 57, 5, '#79827e');
    for (let row = 0; row < 4; row++) {
      for (let col = 0; col < 13; col++) {
        box(13 + col * 17.8, 11 + row * 13, 15.3, 10, 2, row === 0 ? '#313837' : '#414946');
      }
    }
    box(89, 72, 75, 20, 4, '#c7ceca','#a3aaa5');
    ctx.restore();
    ctx.save();
    ctx.transform(1, -.16, .022, 1, 315, 95);
    box(0, 0, 255, 161, 9, metal(0,0,255,160,['#434b49','#141a18','#606a65']), '#78827d');
    box(5, 5, 245, 151, 6, '#18211e');
    ctx.fillStyle = '#a6b7ad';
    ctx.fillRect(120,3,10,1);
    type('Mini Daemon', 17, 22, 10, '#d9e6dc', 650);
    ctx.fillStyle = '#7fbfa3'; ctx.fillRect(227,15,7,3);
    box(14, 32, 225, 113, 4, '#f7f8f3');
    type(m.laptop, 24, 52 + lift, 13, '#26302b', 700);
    box(24, 63, 203, 40, 4, '#e5eae2');
    box(32, 69, 21, 26, 3, current === 0 ? '#506d67' : '#ca522e');
    type(current === 0 ? 'M' : 'PDF', 35, 86, current === 0 ? 10 : 7, '#fff', 700);
    type(m.file, 61, 81, 10.5, '#27372b', 700);
    type('Coursework / CN', 61, 94, 8.5, '#53685c');
    ctx.fillStyle = '#bf502c'; ctx.beginPath(); ctx.arc(28,120,3,0,Math.PI*2); ctx.fill();
    type(m.stage, 38, 124, 10, '#525f54', 600);
    ctx.restore();
  }
  function phone(m, lift) {
    ctx.save();
    ctx.transform(.98, -.22, .10, 1, 100, 147);
    box(-3, 3, 113, 177, 15, '#7a8380');
    box(0, 0, 113, 177, 15, metal(0,0,120,175,['#bec5c0','#202623','#bfc9c2']), '#69746e');
    box(3, 3, 107, 170, 13, '#16201b');
    box(6, 6, 101, 164, 11, '#f7f8f2');
    box(42, 10, 30, 5, 3, '#252c28');
    type('mini', 14, 36, 14, '#27302a', 750);
    ctx.fillStyle = '#cb522c'; ctx.fillRect(14,49,17,3);
    type(m.phone,14,67 + lift,11,'#354638',700);
    type(m.note,14,83,9,'#44504a');
    for (let i=0;i<14;i++) {
      const h = 4 + 10 * Math.abs(Math.sin(i * 1.7));
      box(15+i*5.6,107-h/2,2.7,h,1,'#789289');
    }
    box(13, 127, 86, 22, 4, '#b94523');
    type(m.action,18,141,8,'#fff',650);
    box(44,159,26,2,1,'#7a867d');
    ctx.restore();
  }
  function route(t) {
    const points = [[211,231],[270,230],[234,167],[315,167]];
    ctx.save();
    ctx.beginPath();
    ctx.moveTo(...points[0]);
    ctx.bezierCurveTo(...points[1],...points[2],...points[3]);
    ctx.setLineDash([4,5]);
    ctx.lineWidth = 1.8;
    ctx.strokeStyle = '#83968b'; ctx.stroke();
    ctx.setLineDash([]);
    let p = reduced.matches ? .55 : (t / 2900) % 1;
    if (current === 2) p = 1 - p;
    const q = 1-p;
    const point = [0,1].map(i => q*q*q*points[0][i] + 3*q*q*p*points[1][i] + 3*q*p*p*points[2][i] + p*p*p*points[3][i]);
    ctx.fillStyle = '#ba4924'; ctx.beginPath(); ctx.arc(...point,4.5,0,Math.PI*2); ctx.fill();
    ctx.restore();
  }
  function render(now) {
    frame = 0;
    const scale = canvas.width / 680;
    ctx.setTransform(scale,0,0,scale,0,0);
    ctx.clearRect(0,0,680,370);
    tilt.x += (pointer.x - tilt.x) * .065;
    tilt.y += (pointer.y - tilt.y) * .065;
    ctx.translate(reduced.matches ? 0 : tilt.x, reduced.matches ? 0 : tilt.y);
    shadow(417,280,154,43);
    shadow(164,325,86,16);
    route(now);
    const lift = reduced.matches ? 0 : Math.max(0, 1 - (now - transitionStart) / 300) * 3;
    ctx.save();
    ctx.translate(0, reduced.matches ? 0 : Math.sin(now / 1700) * 2.5);
    laptop(moments[current], lift);
    ctx.restore();
    ctx.save();
    ctx.translate(0, reduced.matches ? 0 : Math.sin(now / 1700 + 1.4) * 4);
    phone(moments[current], lift);
    ctx.restore();
    if (visible && !document.hidden && !reduced.matches) frame = requestAnimationFrame(render);
  }
  function repaint() {
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(render);
  }
  new ResizeObserver(() => {
    const pixels = Math.max(1, Math.round(canvas.clientWidth * Math.min(devicePixelRatio, 2)));
    canvas.width = pixels;
    canvas.height = Math.round(pixels * 370 / 680);
    repaint();
  }).observe(canvas);
  new IntersectionObserver(([entry]) => {
    visible = entry.isIntersecting;
    repaint();
  }).observe(canvas);
  document.querySelectorAll('[data-moment]').forEach(button => button.addEventListener('click', () => {
    current = Number(button.dataset.moment);
    transitionStart = performance.now();
    document.querySelectorAll('[data-moment]').forEach(item => item.setAttribute('aria-pressed', String(item === button)));
    document.getElementById('moment-status').textContent = moments[current].direction;
    canvas.setAttribute('aria-label', moments[current].direction + '. Phone: ' + moments[current].note + '. Laptop: ' + moments[current].stage + '.');
    repaint();
  }));
  canvas.addEventListener('pointermove', event => {
    if (event.pointerType !== 'mouse') return;
    const bounds = canvas.getBoundingClientRect();
    pointer.x = ((event.clientX - bounds.left) / bounds.width - .5) * 15;
    pointer.y = ((event.clientY - bounds.top) / bounds.height - .5) * 10;
  });
  canvas.addEventListener('pointerleave', () => { pointer.x = 0; pointer.y = 0; });
  reduced.addEventListener('change', repaint);
  document.addEventListener('visibilitychange', repaint);
  document.fonts.ready.then(repaint);
})();
