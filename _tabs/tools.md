---
title: Tools
icon: fas fa-tools
order: 4
permalink: /tools/
---

<style>
  :root{
    --tb-acc1:#4fd1c5;
    --tb-acc2:#60a5fa;
  }

  .tools-sub{
    margin: -4px 0 20px;
    opacity: .72;
    font-size: 15px;
    color: rgba(233,238,247,.85);
  }

  .tools-grid{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 16px;
  }

  .tool-card{
    position: relative;
    overflow: hidden;
    border-radius: 16px;
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(0,0,0,.20);
    box-shadow: 0 8px 28px rgba(0,0,0,.30);
    padding: 20px 20px 20px 36px;
    text-decoration: none;
    color: inherit;
    transition: transform .15s ease, border-color .15s ease, box-shadow .15s ease;
    min-height: 130px;
    display: flex;
    flex-direction: column;
    justify-content: center;
  }

  .tool-card:hover{
    transform: translateY(-3px);
    border-color: rgba(255,255,255,.18);
    box-shadow: 0 12px 36px rgba(0,0,0,.40);
  }

  .tool-card::before{
    content:"";
    position: absolute;
    top: 14px;
    bottom: 14px;
    left: 14px;
    width: 4px;
    border-radius: 999px;
    background: linear-gradient(180deg, var(--tb-acc1), var(--tb-acc2));
  }

  .tool-card::after{
    content:"";
    position: absolute;
    inset: 0;
    background:
      radial-gradient(600px 200px at 20% 0%, rgba(79,209,197,.12) 0%, transparent 60%),
      radial-gradient(600px 200px at 80% 0%, rgba(96,165,250,.10) 0%, transparent 60%);
    pointer-events: none;
  }

  .tool-card-inner{
    position: relative;
    z-index: 2;
  }

  .tool-title{
    margin: 0 0 8px;
    font-size: 17px;
    font-weight: 800;
    letter-spacing: .2px;
    color: rgba(245,247,255,.95);
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .tool-desc{
    margin: 0;
    opacity: .78;
    font-size: 14px;
    color: rgba(233,238,247,.85);
    line-height: 1.6;
  }

  .tool-pill{
    display: inline-block;
    margin-top: 14px;
    padding: 5px 12px;
    border-radius: 999px;
    border: 1px solid rgba(79,209,197,.25);
    background: rgba(79,209,197,.08);
    font-size: 12px;
    font-weight: 700;
    color: var(--tb-acc1);
    transition: background .15s ease, border-color .15s ease;
  }

  .tool-card:hover .tool-pill{
    background: rgba(79,209,197,.14);
    border-color: rgba(79,209,197,.40);
  }
</style>

<p class="tools-sub">Utilitários rápidos para apoiar o fluxo de pentest e estudo.</p>

<div class="tools-grid">
  <a class="tool-card" href="/tools/pentestbench/">
    <div class="tool-card-inner">
      <div class="tool-title">🧪 PentestBench</div>
      <p class="tool-desc">Gerador de comandos, cheatsheet e workspace local. Inputs com highlight e copy por comando.</p>
      <span class="tool-pill">Open tool →</span>
    </div>
  </a>
  <a class="tool-card" href="/tools/oscpautopilot/">
    <div class="tool-card-inner">
      <div class="tool-title">🚀 OSCP Autopilot</div>
      <p class="tool-desc">Decision Engine e Checklist para certificação OSCP+. Totalmente executado no navegador.</p>
      <span class="tool-pill">Open tool →</span>
    </div>
  </a>
  <a class="tool-card" href="/tools/oswpautopilot/">
    <div class="tool-card-inner">
      <div class="tool-title">📡 OSWP Autopilot</div>
      <p class="tool-desc">Decision Engine para certificação OSWP (PEN-210). WEP, WPA/WPA2, Evil Twin, WPS e mais.</p>
      <span class="tool-pill">Open tool →</span>
    </div>
  </a>
</div>
