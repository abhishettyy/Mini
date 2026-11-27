// The same printed cover follows the report from the course folder to the form.
class ReportPrint extends HTMLElement {
  connectedCallback() {
    if (this.childElementCount) return;
    this.setAttribute('aria-hidden', 'true');
    this.innerHTML = `
      <span class="print-mast">Northbridge University</span>
      <strong>Computer<br>Networks<span>.</span></strong>
      <canvas width="480" height="216"></canvas>
      <span class="print-course">Lab report</span>
      <span class="print-author">Asha Rao <b>CS24-1187</b></span>`;

    const ink = this.querySelector('canvas').getContext('2d');
    if (!ink) return;
    const nodes = [[46,114],[132,54],[148,159],[259,84],[333,155],[428,68]];
    ink.fillStyle = '#b6b6a0';
    for (let x = 9; x < 480; x += 21) {
      for (let y = 9; y < 216; y += 21) ink.fillRect(x, y, 2, 2);
    }
    ink.lineWidth = 2.5;
    [[0,1],[0,2],[1,2],[1,3],[2,3],[2,4],[3,4],[3,5],[4,5]].forEach(([a,b]) => {
      ink.beginPath();
      ink.moveTo(...nodes[a]);
      ink.lineTo(...nodes[b]);
      ink.strokeStyle = '#335646';
      ink.stroke();
    });
    nodes.forEach(([x,y], i) => {
      ink.beginPath();
      ink.arc(x,y,i === 3 ? 15 : 10,0,Math.PI * 2);
      ink.fillStyle = i === 3 ? '#b54726' : '#f4f0dc';
      ink.fill();
      ink.stroke();
    });
  }
}
customElements.define('cn-report', ReportPrint);
