import { useState, useEffect } from "react";
import axios from "axios";

export const API = "https://cyber-threat-monitor-mm0f.onrender.com";

export const injectStyles = () => {
  if (document.getElementById("ctm-global")) return;
  const s = document.createElement("style");
  s.id = "ctm-global";
  s.textContent = `
    @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;600;700;800&display=swap');
    *, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }
    html, body, #root { height:100%; }
    body { font-family:'Syne',sans-serif; overflow-x:hidden; }
    ::-webkit-scrollbar { width:4px; height:4px; }
    ::-webkit-scrollbar-track { background:transparent; }
    ::-webkit-scrollbar-thumb { background:#3a2a6a; border-radius:99px; }
    @keyframes fadeUp  { from{opacity:0;transform:translateY(14px)} to{opacity:1;transform:none} }
    @keyframes fadeIn  { from{opacity:0} to{opacity:1} }
    @keyframes spin    { to{transform:rotate(360deg)} }
    @keyframes ping    { 75%,100%{transform:scale(2);opacity:0} }
    @keyframes shimmer { 0%{background-position:200% 0} 100%{background-position:-200% 0} }
    @keyframes glow    { 0%,100%{box-shadow:0 0 10px #7c3aed55} 50%{box-shadow:0 0 22px #7c3aedaa} }
    @keyframes typing  { 0%,100%{opacity:1} 50%{opacity:0.3} }
  `;
  document.head.appendChild(s);
};

export const DARK = {
  bg:"#08071a", card:"#100f28", sidebar:"#0b0a20", input:"#18163a",
  border:"#2a2550", borderHi:"#4a3f8a",
  accent:"#8b5cf6", accentSoft:"rgba(139,92,246,0.1)",
  text:"#ede9fe", textMuted:"#9d8ec7", textDim:"#5a4f7a",
  high:"#f87171", highBg:"rgba(248,113,113,0.1)",
  mid:"#fbbf24",  midBg:"rgba(251,191,36,0.1)",
  low:"#34d399",  lowBg:"rgba(52,211,153,0.1)",
};
export const LIGHT = {
  bg:"#f5f3ff", card:"#ffffff", sidebar:"#1e1148", input:"#ede9fe",
  border:"#ddd6fe", borderHi:"#a78bfa",
  accent:"#7c3aed", accentSoft:"rgba(124,58,237,0.07)",
  text:"#1e1148", textMuted:"#6d5c9e", textDim:"#b0a4d8",
  high:"#dc2626", highBg:"rgba(220,38,38,0.07)",
  mid:"#d97706",  midBg:"rgba(217,119,6,0.07)",
  low:"#059669",  lowBg:"rgba(5,150,105,0.07)",
};

export const sc = (t,s) => ({HIGH:t.high,MEDIUM:t.mid,LOW:t.low}[s]||t.accent);
export const sb = (t,s) => ({HIGH:t.highBg,MEDIUM:t.midBg,LOW:t.lowBg}[s]||t.accentSoft);

export const apiClient = axios.create({ baseURL: API });
apiClient.interceptors.request.use(cfg => {
  const tok = localStorage.getItem("ctm_token");
  if (tok) cfg.headers.Authorization = `Bearer ${tok}`;
  return cfg;
});

export const MOCK_ALERTS = [
  {id:1,timestamp:new Date().toISOString(),severity:"HIGH",  severity_score:0.91,ip_addresses:"203.0.113.5",  log_text:"failed login [SEP] failed login [SEP] account locked",explanation:["Brute force","Account lockout"]},
  {id:2,timestamp:new Date().toISOString(),severity:"HIGH",  severity_score:0.87,ip_addresses:"198.51.100.42",log_text:"port scan [SEP] unauthorized access attempt",            explanation:["Port scan","Unauthorized access"]},
  {id:3,timestamp:new Date().toISOString(),severity:"MEDIUM",severity_score:0.58,ip_addresses:"10.0.0.99",    log_text:"privilege escalation attempt on server",                 explanation:["Privilege escalation"]},
  {id:4,timestamp:new Date().toISOString(),severity:"MEDIUM",severity_score:0.52,ip_addresses:"172.16.0.5",   log_text:"multiple failed ssh login attempts",                     explanation:["Brute force"]},
  {id:5,timestamp:new Date().toISOString(),severity:"LOW",   severity_score:0.24,ip_addresses:"",             log_text:"backup completed with warnings",                         explanation:[]},
  {id:6,timestamp:new Date().toISOString(),severity:"LOW",   severity_score:0.19,ip_addresses:"",             log_text:"session expired auto logout",                            explanation:[]},
];

export const Ico = ({ d, s=20 }) => (
  <svg width={s} height={s} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round">
    <path d={d} />
  </svg>
);

export const I = {
  dash:   "M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z M9 22V12h6v10",
  bell:   "M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9 M13.73 21a2 2 0 01-3.46 0",
  up:     "M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4 M17 8l-5-5-5 5 M12 3v12",
  cog:    "M12 15a3 3 0 100-6 3 3 0 000 6z M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z",
  moon:   "M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z",
  sun:    "M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42 M12 17a5 5 0 100-10 5 5 0 000 10z",
  menu:   "M3 12h18M3 6h18M3 18h18",
  x:      "M18 6L6 18M6 6l12 12",
  shield: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
  logout: "M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9",
  user:   "M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2 M12 11a4 4 0 100-8 4 4 0 000 8z",
  hist:   "M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z",
  eye:    "M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z M12 9a3 3 0 100 6 3 3 0 000-6z",
  eyeO:   "M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24M1 1l22 22",
  chat:   "M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z",
  key:    "M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4",
  check:  "M20 6L9 17l-5-5",
  info:   "M12 22a10 10 0 100-20 10 10 0 000 20z M12 16v-4 M12 8h.01",
  mail:   "M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z M22 6l-10 7L2 6",
  phone:  "M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07A19.5 19.5 0 013.15 9.8a19.79 19.79 0 01-3.07-8.67A2 2 0 012.06 0h3a2 2 0 012 1.72c.127.96.361 1.903.7 2.81a2 2 0 01-.45 2.11L6.09 7.91a16 16 0 006 6l1.27-1.27a2 2 0 012.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0122 16.92z",
  save:   "M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z M17 21v-8H7v8 M7 3v5h8",
};

export const Spinner = () => (
  <span style={{width:15,height:15,border:"2px solid #ffffff30",borderTopColor:"#fff",
    borderRadius:"50%",display:"inline-block",animation:"spin .7s linear infinite"}} />
);
export const Pulse = ({ color }) => (
  <span style={{position:"relative",display:"inline-block",width:9,height:9,flexShrink:0}}>
    <span style={{position:"absolute",inset:0,borderRadius:"50%",background:color,
      opacity:.4,animation:"ping 1.4s cubic-bezier(0,0,.2,1) infinite"}} />
    <span style={{position:"absolute",inset:"2px",borderRadius:"50%",background:color}} />
  </span>
);
export const Badge = ({ label, t }) => (
  <span style={{display:"inline-flex",alignItems:"center",gap:5,padding:"3px 9px",
    borderRadius:20,background:sb(t,label),color:sc(t,label),
    fontSize:10,fontWeight:700,letterSpacing:".05em",fontFamily:"'Space Mono',monospace",
    border:`1px solid ${sc(t,label)}33`}}>
    <Pulse color={sc(t,label)} />{label}
  </span>
);
export const Skel = ({ h=13, w="100%", t }) => (
  <div style={{height:h,width:w,borderRadius:6,background:t.border,
    backgroundImage:`linear-gradient(90deg,${t.border} 0%,${t.borderHi} 50%,${t.border} 100%)`,
    backgroundSize:"200% 100%",animation:"shimmer 1.5s infinite"}} />
);

const inputSt = (t) => ({
  width:"100%", padding:"11px 13px", borderRadius:9,
  background:t.input, border:`1px solid ${t.border}`,
  color:t.text, fontSize:14, fontFamily:"'Syne',sans-serif", outline:"none",
});

export function AuthLayout({ children, t }) {
  return (
    <div style={{minHeight:"100vh",display:"flex",alignItems:"center",
      justifyContent:"center",background:t.bg,padding:16}}>
      <div style={{position:"fixed",top:"15%",left:"50%",transform:"translateX(-50%)",
        width:480,height:480,borderRadius:"50%",
        background:"radial-gradient(circle,rgba(139,92,246,0.11) 0%,transparent 70%)",
        pointerEvents:"none"}} />
      <div style={{width:"100%",maxWidth:420,animation:"fadeUp .45s ease"}}>
        <div style={{textAlign:"center",marginBottom:28}}>
          <div style={{width:52,height:52,borderRadius:13,margin:"0 auto 12px",
            background:"linear-gradient(135deg,#8b5cf6,#ec4899)",
            display:"flex",alignItems:"center",justifyContent:"center",
            animation:"glow 3s ease-in-out infinite"}}>
            <Ico d={I.shield} s={24} />
          </div>
          <h1 style={{fontSize:22,fontWeight:800,color:t.text,letterSpacing:"-.02em"}}>
            CyberAI Monitor
          </h1>
          <p style={{fontSize:11,color:t.textMuted,marginTop:4,fontFamily:"'Space Mono',monospace"}}>
            Threat Intelligence Platform
          </p>
        </div>
        <div style={{background:t.card,border:`1px solid ${t.border}`,borderRadius:18,padding:28}}>
          {children}
        </div>
      </div>
    </div>
  );
}

function Field({ label, children, t }) {
  return (
    <div style={{marginBottom:14}}>
      <label style={{fontSize:11,color:t.textMuted,display:"block",marginBottom:5,fontWeight:600}}>
        {label}
      </label>
      {children}
    </div>
  );
}
function ErrBox({ msg, t }) {
  return (
    <div style={{padding:"9px 12px",borderRadius:7,background:t.highBg,
      color:t.high,fontSize:12,marginBottom:14,border:`1px solid ${t.high}33`}}>
      {msg}
    </div>
  );
}
function SubmitBtn({ loading, label, t }) {
  return (
    <button type="submit" disabled={loading}
      style={{width:"100%",padding:"11px",borderRadius:9,border:"none",
        cursor:loading?"not-allowed":"pointer",
        background:loading?t.border:"linear-gradient(135deg,#8b5cf6,#ec4899)",
        color:"#fff",fontWeight:700,fontSize:14,fontFamily:"'Syne',sans-serif",
        display:"flex",alignItems:"center",justifyContent:"center",gap:8,marginTop:4}}>
      {loading?<><Spinner />{label}...</>:label}
    </button>
  );
}
function SwitchLink({ text, link, onClick, t }) {
  return (
    <p style={{textAlign:"center",fontSize:12,color:t.textMuted,marginTop:16}}>
      {text}{" "}
      <button onClick={onClick} style={{background:"none",border:"none",cursor:"pointer",
        color:t.accent,fontWeight:700,fontSize:12,fontFamily:"'Syne',sans-serif",
        textDecoration:"underline"}}>
        {link}
      </button>
    </p>
  );
}

function LoginPage({ onLogin, onSwitch, t }) {
  const [u,setU]=useState(""); const [p,setP]=useState("");
  const [show,setShow]=useState(false);
  const [loading,setLoading]=useState(false); const [err,setErr]=useState("");
  const submit = async e => {
    e.preventDefault();
    if(!u||!p){setErr("Please fill in all fields");return;}
    setLoading(true);setErr("");
    try {
      const fd=new FormData(); fd.append("username",u); fd.append("password",p);
      const r=await apiClient.post("/auth/login",fd);
      localStorage.setItem("ctm_token",r.data.access_token);
      onLogin(r.data.user);
    } catch(ex) {
      if(u==="admin"&&p==="admin123"){
        localStorage.setItem("ctm_token","demo");
        onLogin({username:"admin",full_name:"Admin User",role:"admin",email:"admin@cyberai.com"});
      } else setErr(ex.response?.data?.detail||"Invalid credentials");
    }
    setLoading(false);
  };
  return (
    <AuthLayout t={t}>
      <h2 style={{fontSize:17,fontWeight:800,color:t.text,marginBottom:22}}>Sign in</h2>
      <form onSubmit={submit}>
        <Field label="Username" t={t}>
          <input value={u} onChange={e=>setU(e.target.value)} placeholder="admin"
            style={inputSt(t)} onFocus={e=>e.target.style.borderColor=t.accent}
            onBlur={e=>e.target.style.borderColor=t.border} />
        </Field>
        <Field label="Password" t={t}>
          <div style={{position:"relative"}}>
            <input value={p} onChange={e=>setP(e.target.value)}
              type={show?"text":"password"} placeholder="••••••••"
              style={{...inputSt(t),paddingRight:42}}
              onFocus={e=>e.target.style.borderColor=t.accent}
              onBlur={e=>e.target.style.borderColor=t.border} />
            <button type="button" onClick={()=>setShow(s=>!s)}
              style={{position:"absolute",right:11,top:"50%",transform:"translateY(-50%)",
                background:"none",border:"none",cursor:"pointer",color:t.textMuted,
                display:"flex",alignItems:"center"}}>
              <Ico d={show?I.eyeO:I.eye} s={15} />
            </button>
          </div>
        </Field>
        {err&&<ErrBox msg={err} t={t}/>}
        <SubmitBtn loading={loading} label="Sign in" t={t}/>
      </form>
      <div style={{marginTop:16,padding:"10px 12px",borderRadius:7,
        background:t.accentSoft,border:`1px solid ${t.border}`}}>
        <p style={{fontSize:11,color:t.textMuted,fontFamily:"'Space Mono',monospace"}}>
          Demo — <strong style={{color:t.accent}}>admin</strong> /
          <strong style={{color:t.accent}}> admin123</strong>
        </p>
      </div>
      <SwitchLink t={t} text="Don't have an account?" link="Create one" onClick={onSwitch}/>
    </AuthLayout>
  );
}

function RegisterPage({ onLogin, onSwitch, t }) {
  const [form,setForm]=useState({username:"",email:"",full_name:"",password:"",confirm:""});
  const [show,setShow]=useState(false);
  const [loading,setLoading]=useState(false); const [err,setErr]=useState("");
  const [success,setSuccess]=useState(false);
  const set = k => e => setForm(f=>({...f,[k]:e.target.value}));
  const submit = async e => {
    e.preventDefault(); setErr("");
    if(!form.username||!form.email||!form.full_name||!form.password){setErr("Please fill in all fields");return;}
    if(form.password!==form.confirm){setErr("Passwords do not match");return;}
    if(form.password.length<6){setErr("Password must be at least 6 characters");return;}
    setLoading(true);
    try {
      await apiClient.post("/auth/register",{
        username:form.username,email:form.email,
        full_name:form.full_name,password:form.password,role:"analyst",
      });
      const fd=new FormData(); fd.append("username",form.username); fd.append("password",form.password);
      const r=await apiClient.post("/auth/login",fd);
      localStorage.setItem("ctm_token",r.data.access_token);
      setSuccess(true); setTimeout(()=>onLogin(r.data.user),1200);
    } catch(ex){setErr(ex.response?.data?.detail||"Registration failed.");}
    setLoading(false);
  };
  if(success) return (
    <AuthLayout t={t}>
      <div style={{textAlign:"center",padding:"24px 0"}}>
        <div style={{width:56,height:56,borderRadius:"50%",
          background:"rgba(52,211,153,0.15)",border:"2px solid #34d399",
          display:"flex",alignItems:"center",justifyContent:"center",margin:"0 auto 16px"}}>
          <Ico d={I.check} s={28}/>
        </div>
        <div style={{fontSize:17,fontWeight:800,color:t.low,marginBottom:8}}>Account created!</div>
        <div style={{fontSize:13,color:t.textMuted}}>Signing you in...</div>
      </div>
    </AuthLayout>
  );
  return (
    <AuthLayout t={t}>
      <h2 style={{fontSize:17,fontWeight:800,color:t.text,marginBottom:22}}>Create account</h2>
      <form onSubmit={submit}>
        <Field label="Full name" t={t}><input value={form.full_name} onChange={set("full_name")} placeholder="Your full name" style={inputSt(t)} onFocus={e=>e.target.style.borderColor=t.accent} onBlur={e=>e.target.style.borderColor=t.border}/></Field>
        <Field label="Username" t={t}><input value={form.username} onChange={set("username")} placeholder="Choose a username" style={inputSt(t)} onFocus={e=>e.target.style.borderColor=t.accent} onBlur={e=>e.target.style.borderColor=t.border}/></Field>
        <Field label="Email" t={t}><input value={form.email} onChange={set("email")} type="email" placeholder="you@example.com" style={inputSt(t)} onFocus={e=>e.target.style.borderColor=t.accent} onBlur={e=>e.target.style.borderColor=t.border}/></Field>
        <Field label="Password" t={t}>
          <div style={{position:"relative"}}>
            <input value={form.password} onChange={set("password")} type={show?"text":"password"} placeholder="Min 6 characters" style={{...inputSt(t),paddingRight:42}} onFocus={e=>e.target.style.borderColor=t.accent} onBlur={e=>e.target.style.borderColor=t.border}/>
            <button type="button" onClick={()=>setShow(s=>!s)} style={{position:"absolute",right:11,top:"50%",transform:"translateY(-50%)",background:"none",border:"none",cursor:"pointer",color:t.textMuted,display:"flex",alignItems:"center"}}><Ico d={show?I.eyeO:I.eye} s={15}/></button>
          </div>
        </Field>
        <Field label="Confirm password" t={t}><input value={form.confirm} onChange={set("confirm")} type="password" placeholder="Repeat password" style={inputSt(t)} onFocus={e=>e.target.style.borderColor=t.accent} onBlur={e=>e.target.style.borderColor=t.border}/></Field>
        {err&&<ErrBox msg={err} t={t}/>}
        <SubmitBtn loading={loading} label="Create account" t={t}/>
      </form>
      <SwitchLink t={t} text="Already have an account?" link="Sign in" onClick={onSwitch}/>
    </AuthLayout>
  );
}

export function AuthPages({ onLogin, t }) {
  const [mode,setMode]=useState("login");
  return mode==="login"
    ?<LoginPage onLogin={onLogin} onSwitch={()=>setMode("register")} t={t}/>
    :<RegisterPage onLogin={onLogin} onSwitch={()=>setMode("login")} t={t}/>;
}

export function ApiKeyGuide({ t }) {
  const steps=[
    {n:"1",title:"Go to Anthropic Console",desc:"Open console.anthropic.com in your browser",link:"https://console.anthropic.com",linkText:"Open console →"},
    {n:"2",title:"Create a free account",desc:"Sign up with your email. No credit card needed for free tier."},
    {n:"3",title:"Go to API Keys",desc:'Click "API Keys" in the left sidebar, then click "Create Key".'},
    {n:"4",title:"Copy and paste your key below",desc:"Your key looks like: sk-ant-api03-xxxx... Paste it in the box below."},
  ];
  return (
    <div style={{background:t.card,border:`1px solid ${t.border}`,borderRadius:14,padding:22,marginBottom:14,animation:"fadeUp .4s ease"}}>
      <div style={{fontSize:14,fontWeight:800,marginBottom:4}}>Get your free Anthropic API key</div>
      <div style={{fontSize:11,color:t.textMuted,marginBottom:18,fontFamily:"'Space Mono',monospace"}}>Follow these 4 steps — takes 2 minutes</div>
      {steps.map((s,i)=>(
        <div key={i} style={{display:"flex",gap:12,marginBottom:14,animation:`fadeUp .3s ease ${i*0.08}s both`}}>
          <div style={{width:28,height:28,borderRadius:"50%",flexShrink:0,background:`linear-gradient(135deg,${t.accent},#ec4899)`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:12,fontWeight:800,color:"#fff"}}>{s.n}</div>
          <div style={{flex:1}}>
            <div style={{fontSize:13,fontWeight:700,marginBottom:2}}>{s.title}</div>
            <div style={{fontSize:11,color:t.textMuted,lineHeight:1.5}}>{s.desc}</div>
            {s.link&&<a href={s.link} target="_blank" rel="noreferrer" style={{display:"inline-block",marginTop:6,fontSize:11,color:t.accent,fontWeight:700,textDecoration:"none",padding:"3px 10px",borderRadius:20,background:t.accentSoft,border:`1px solid ${t.accent}33`}}>{s.linkText}</a>}
          </div>
        </div>
      ))}
      <div style={{padding:"10px 14px",borderRadius:8,background:"rgba(251,191,36,0.08)",border:"1px solid rgba(251,191,36,0.25)",fontSize:11,color:t.mid}}>
        Free tier gives you $5 credit — enough for hundreds of conversations. Your key is stored only in your browser.
      </div>
    </div>
  );
}

export function AnalysisResult({ result, t }) {
  const isA=result.is_anomaly; const sev=result.severity?.level||"LOW";
  return (
    <div style={{background:t.card,border:`1px solid ${isA?sc(t,sev):t.border}`,borderRadius:12,padding:20,animation:"fadeUp .3s ease"}}>
      <div style={{display:"flex",alignItems:"center",gap:9,flexWrap:"wrap",marginBottom:14}}>
        <span style={{fontSize:14,fontWeight:800}}>Result</span>
        <Badge label={isA?sev:"NORMAL"} t={t}/>
        {result.severity&&<span style={{fontSize:10,color:t.textMuted,fontFamily:"'Space Mono',monospace"}}>score: {result.severity.score}</span>}
      </div>
      {result.anomalies_found!==undefined&&(
        <div style={{fontSize:12,color:t.textMuted,marginBottom:10}}>
          Found <strong style={{color:t.accent}}>{result.anomalies_found}</strong> anomalies in <strong style={{color:t.accent}}>{result.total_sequences}</strong> sequences
        </div>
      )}
      {result.explanation?.length>0&&(
        <div style={{display:"flex",flexDirection:"column",gap:6}}>
          <div style={{fontSize:10,color:t.textMuted,fontFamily:"'Space Mono',monospace",marginBottom:3}}>Why flagged:</div>
          {result.explanation.map((r,i)=>(
            <div key={i} style={{padding:"8px 11px",borderRadius:6,background:t.accentSoft,borderLeft:`3px solid ${t.accent}`,fontSize:12,animation:`fadeUp .22s ease ${i*0.05}s both`}}>{r}</div>
          ))}
        </div>
      )}
      {result.entities&&(
        <div style={{display:"flex",gap:7,flexWrap:"wrap",marginTop:12}}>
          {result.entities.ips?.length>0&&<div style={{padding:"5px 10px",borderRadius:6,background:t.highBg,border:`1px solid ${t.high}33`,fontSize:10,color:t.high,fontFamily:"'Space Mono',monospace"}}>IP: {result.entities.ips.join(", ")}</div>}
          {result.entities.users?.length>0&&<div style={{padding:"5px 10px",borderRadius:6,background:t.midBg,border:`1px solid ${t.mid}33`,fontSize:10,color:t.mid,fontFamily:"'Space Mono',monospace"}}>User: {result.entities.users.join(", ")}</div>}
        </div>
      )}
    </div>
  );
}

export function AlertsTable({ alerts, loading, t, full, mobile }) {
  const [search,setSearch]=useState("");
  const [sevFilter,setSevFilter]=useState("ALL");
  const filtered=alerts.filter(a=>{
    const matchSev=sevFilter==="ALL"||a.severity===sevFilter;
    const matchSearch=!search||(a.log_text||"").toLowerCase().includes(search.toLowerCase())||(a.ip_addresses||"").includes(search);
    return matchSev&&matchSearch;
  });
  return (
    <div style={{background:t.card,border:`1px solid ${t.border}`,borderRadius:12,overflow:"hidden"}}>
      <div style={{padding:"14px 18px",borderBottom:`1px solid ${t.border}`,display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:10}}>
        <div>
          <div style={{fontSize:13,fontWeight:700}}>{full?"All alerts":"Recent alerts"}</div>
          <div style={{fontSize:9,color:t.textMuted,fontFamily:"'Space Mono',monospace",marginTop:1}}>{filtered.length} of {alerts.length} shown</div>
        </div>
        {full&&(
          <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
            <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search logs or IPs..."
              style={{padding:"6px 10px",borderRadius:7,fontSize:11,background:t.input,border:`1px solid ${t.border}`,color:t.text,outline:"none",fontFamily:"'Space Mono',monospace",width:180}}
              onFocus={e=>e.target.style.borderColor=t.accent} onBlur={e=>e.target.style.borderColor=t.border}/>
            <select value={sevFilter} onChange={e=>setSevFilter(e.target.value)}
              style={{padding:"6px 10px",borderRadius:7,fontSize:11,background:t.input,border:`1px solid ${t.border}`,color:t.text,outline:"none",cursor:"pointer"}}>
              {["ALL","HIGH","MEDIUM","LOW"].map(s=><option key={s} value={s}>{s}</option>)}
            </select>
          </div>
        )}
      </div>
      <div style={{overflowX:"auto"}}>
        <table style={{width:"100%",borderCollapse:"collapse",minWidth:mobile?480:0}}>
          <thead>
            <tr style={{borderBottom:`1px solid ${t.border}`}}>
              {["Time","Severity","IP","Log preview","Score"].map(h=>(
                <th key={h} style={{padding:"9px 13px",textAlign:"left",fontSize:9,color:t.textMuted,fontWeight:600,fontFamily:"'Space Mono',monospace",letterSpacing:".05em",whiteSpace:"nowrap"}}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading?Array.from({length:4}).map((_,i)=>(
              <tr key={i}>{Array.from({length:5}).map((_,j)=>(
                <td key={j} style={{padding:"11px 13px"}}><Skel t={t} h={10}/></td>
              ))}</tr>
            )):filtered.length===0?(
              <tr><td colSpan={5} style={{padding:"32px",textAlign:"center",color:t.textMuted,fontSize:12}}>No alerts found. Analyze some logs to get started.</td></tr>
            ):filtered.map((a,i)=>(
              <tr key={a.id||i} style={{borderBottom:`1px solid ${t.border}15`,transition:"background .12s",animation:`fadeUp .22s ease ${i*0.04}s both`}}
                onMouseEnter={e=>e.currentTarget.style.background=t.accentSoft}
                onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                <td style={{padding:"10px 13px",fontSize:10,color:t.textMuted,fontFamily:"'Space Mono',monospace",whiteSpace:"nowrap"}}>{a.timestamp?new Date(a.timestamp).toLocaleTimeString():"--:--"}</td>
                <td style={{padding:"10px 13px"}}><Badge label={a.severity||"LOW"} t={t}/></td>
                <td style={{padding:"10px 13px",fontSize:10,color:t.mid,fontFamily:"'Space Mono',monospace",whiteSpace:"nowrap"}}>{a.ip_addresses||"—"}</td>
                <td style={{padding:"10px 13px",fontSize:10,color:t.textMuted,maxWidth:220,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{a.log_text||"—"}</td>
                <td style={{padding:"10px 13px",fontSize:10,fontFamily:"'Space Mono',monospace",color:sc(t,a.severity)}}>{a.severity_score?.toFixed(2)||"0.00"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function ProfilePage({ user, loginHist, t }) {
  return (
    <div style={{display:"flex",flexDirection:"column",gap:12}}>
      <div style={{background:t.card,border:`1px solid ${t.border}`,borderRadius:14,overflow:"hidden"}}>
        <div style={{height:80,background:"linear-gradient(135deg,#8b5cf6 0%,#ec4899 50%,#3b82f6 100%)"}}/>
        <div style={{padding:"0 22px 22px",marginTop:-24}}>
          <div style={{width:50,height:50,borderRadius:"50%",background:"linear-gradient(135deg,#8b5cf6,#ec4899)",border:`4px solid ${t.card}`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:20,fontWeight:800,color:"#fff",marginBottom:9}}>
            {(user.full_name||user.username||"?")[0].toUpperCase()}
          </div>
          <div style={{fontSize:17,fontWeight:800}}>{user.full_name||user.username}</div>
          <div style={{fontSize:11,color:t.textMuted,fontFamily:"'Space Mono',monospace",marginTop:2}}>@{user.username} · {user.role}</div>
          <div style={{fontSize:11,color:t.textMuted,marginTop:3}}>{user.email}</div>
          {user.last_login&&<div style={{fontSize:10,color:t.textDim,marginTop:3,fontFamily:"'Space Mono',monospace"}}>Last login: {new Date(user.last_login).toLocaleString()}</div>}
        </div>
      </div>
      <div style={{background:t.card,border:`1px solid ${t.border}`,borderRadius:12,overflow:"hidden"}}>
        <div style={{padding:"13px 16px",borderBottom:`1px solid ${t.border}`,display:"flex",alignItems:"center",gap:7}}>
          <Ico d={I.hist} s={15}/><span style={{fontSize:13,fontWeight:700}}>Login history</span>
        </div>
        {loginHist.length===0?(
          <div style={{padding:"22px",textAlign:"center",fontSize:12,color:t.textMuted}}>No history available</div>
        ):loginHist.map((h,i)=>(
          <div key={i} style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"10px 16px",borderBottom:`1px solid ${t.border}15`}}>
            <div>
              <div style={{fontSize:11,color:t.text,fontFamily:"'Space Mono',monospace"}}>{new Date(h.timestamp).toLocaleString()}</div>
              <div style={{fontSize:10,color:t.textMuted,marginTop:1}}>{h.ip_address}</div>
            </div>
            <span style={{fontSize:10,fontWeight:700,padding:"2px 8px",borderRadius:20,background:h.success?t.lowBg:t.highBg,color:h.success?t.low:t.high}}>{h.success?"SUCCESS":"FAILED"}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Settings Page with Notification Preferences ───────────────────────────────
export function SettingsPage({ dark, setDark, t, onLogout }) {
  const [notifPrefs, setNotifPrefs] = useState({
    notify_email: false,
    notify_sms: false,
    notify_phone: "",
    notify_min_severity: "HIGH",
  });
  const [saving, setSaving]   = useState(false);
  const [saved,  setSaved]    = useState(false);
  const [uiDark, setUiDark]   = useState(dark);
  const [live,   setLive]     = useState(true);

  useEffect(() => {
    apiClient.get("/notifications/prefs")
      .then(r => setNotifPrefs(r.data))
      .catch(() => {});
  }, []);

  const savePrefs = async () => {
    setSaving(true);
    try {
      await apiClient.put("/notifications/prefs", notifPrefs);
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } catch (e) {
      console.error(e);
    }
    setSaving(false);
  };

  const Toggle = ({ val, fn }) => (
    <button onClick={fn} style={{width:38,height:20,borderRadius:10,border:"none",
      cursor:"pointer",background:val?t.accent:t.border,position:"relative",transition:"background .2s"}}>
      <span style={{position:"absolute",top:2,left:val?20:2,width:16,height:16,
        borderRadius:"50%",background:"#fff",transition:"left .2s"}}/>
    </button>
  );

  return (
    <div style={{display:"flex",flexDirection:"column",gap:12}}>

      {/* UI Preferences */}
      <div style={{background:t.card,border:`1px solid ${t.border}`,borderRadius:12,padding:20}}>
        <div style={{fontSize:13,fontWeight:700,marginBottom:14}}>Appearance</div>
        {[
          {label:"Dark mode",       sub:"Purple dark theme",      val:uiDark, fn:()=>{setUiDark(d=>!d);setDark(d=>!d);}},
          {label:"Live monitoring", sub:"Auto-refresh every 30s", val:live,   fn:()=>setLive(v=>!v)},
        ].map(item=>(
          <div key={item.label} style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"11px 0",borderBottom:`1px solid ${t.border}18`}}>
            <div>
              <div style={{fontSize:12,fontWeight:600}}>{item.label}</div>
              <div style={{fontSize:10,color:t.textMuted,marginTop:1}}>{item.sub}</div>
            </div>
            <Toggle val={item.val} fn={item.fn}/>
          </div>
        ))}
      </div>

      {/* Notification Preferences */}
      <div style={{background:t.card,border:`1px solid ${t.border}`,borderRadius:12,padding:20}}>
        <div style={{fontSize:13,fontWeight:700,marginBottom:4,display:"flex",alignItems:"center",gap:8}}>
          <Ico d={I.bell} s={16}/> Alert notifications
        </div>
        <div style={{fontSize:11,color:t.textMuted,marginBottom:16,fontFamily:"'Space Mono',monospace"}}>
          Get notified when threats are detected
        </div>

        {/* Email toggle */}
        <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",
          padding:"12px 0",borderBottom:`1px solid ${t.border}18`}}>
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <div style={{width:32,height:32,borderRadius:8,background:t.accentSoft,
              display:"flex",alignItems:"center",justifyContent:"center",color:t.accent}}>
              <Ico d={I.mail} s={15}/>
            </div>
            <div>
              <div style={{fontSize:12,fontWeight:600}}>Email alerts</div>
              <div style={{fontSize:10,color:t.textMuted,marginTop:1}}>
                Sent to: {notifPrefs.notify_email ? "your registered email" : "disabled"}
              </div>
            </div>
          </div>
          <Toggle
            val={notifPrefs.notify_email}
            fn={()=>setNotifPrefs(p=>({...p,notify_email:!p.notify_email}))}/>
        </div>

        {/* SMS toggle */}
        <div style={{padding:"12px 0",borderBottom:`1px solid ${t.border}18`}}>
          <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:notifPrefs.notify_sms?12:0}}>
            <div style={{display:"flex",alignItems:"center",gap:10}}>
              <div style={{width:32,height:32,borderRadius:8,background:t.accentSoft,
                display:"flex",alignItems:"center",justifyContent:"center",color:t.accent}}>
                <Ico d={I.phone} s={15}/>
              </div>
              <div>
                <div style={{fontSize:12,fontWeight:600}}>SMS alerts</div>
                <div style={{fontSize:10,color:t.textMuted,marginTop:1}}>
                  Sent via Twilio to your phone
                </div>
              </div>
            </div>
            <Toggle
              val={notifPrefs.notify_sms}
              fn={()=>setNotifPrefs(p=>({...p,notify_sms:!p.notify_sms}))}/>
          </div>
          {notifPrefs.notify_sms && (
            <div style={{animation:"fadeUp .2s ease"}}>
              <input
                value={notifPrefs.notify_phone}
                onChange={e=>setNotifPrefs(p=>({...p,notify_phone:e.target.value}))}
                placeholder="+919876543210 (include country code)"
                style={{width:"100%",padding:"9px 12px",borderRadius:8,background:t.input,
                  border:`1px solid ${t.border}`,color:t.text,fontSize:12,outline:"none",
                  fontFamily:"'Space Mono',monospace",marginTop:4}}
                onFocus={e=>e.target.style.borderColor=t.accent}
                onBlur={e=>e.target.style.borderColor=t.border}/>
              <div style={{fontSize:10,color:t.textMuted,marginTop:5}}>
                Requires Twilio configured in server .env file.
                <a href="https://twilio.com" target="_blank" rel="noreferrer"
                  style={{color:t.accent,marginLeft:4,textDecoration:"none"}}>
                  Get free trial →
                </a>
              </div>
            </div>
          )}
        </div>

        {/* Min severity */}
        <div style={{padding:"12px 0",borderBottom:`1px solid ${t.border}18`}}>
          <div style={{fontSize:12,fontWeight:600,marginBottom:8}}>Minimum severity to notify</div>
          <div style={{display:"flex",gap:8}}>
            {["LOW","MEDIUM","HIGH"].map(sev=>{
              const active = notifPrefs.notify_min_severity === sev;
              const color  = {LOW:t.low,MEDIUM:t.mid,HIGH:t.high}[sev];
              return (
                <button key={sev} onClick={()=>setNotifPrefs(p=>({...p,notify_min_severity:sev}))}
                  style={{flex:1,padding:"8px",borderRadius:8,border:`1px solid ${active?color:t.border}`,
                    cursor:"pointer",background:active?`${color}18`:"transparent",
                    color:active?color:t.textMuted,fontSize:11,fontWeight:700,
                    fontFamily:"'Space Mono',monospace",transition:"all .15s"}}>
                  {sev}
                </button>
              );
            })}
          </div>
          <div style={{fontSize:10,color:t.textMuted,marginTop:6}}>
            You will be notified for {notifPrefs.notify_min_severity} and above
          </div>
        </div>

        {/* Save button */}
        <button onClick={savePrefs} disabled={saving}
          style={{marginTop:16,width:"100%",padding:"10px",borderRadius:9,border:"none",
            cursor:saving?"not-allowed":"pointer",
            background:saved?"rgba(52,211,153,0.15)":saving?t.border
              :"linear-gradient(135deg,#8b5cf6,#ec4899)",
            color:saved?t.low:"#fff",fontWeight:700,fontSize:13,
            fontFamily:"'Syne',sans-serif",
            display:"flex",alignItems:"center",justifyContent:"center",gap:8,
            transition:"all .2s"}}>
          {saving ? <><Spinner/>Saving...</>
            : saved ? <><Ico d={I.check} s={15}/>Preferences saved!</>
            : <><Ico d={I.save} s={15}/>Save notification settings</>}
        </button>
      </div>

      {/* System info */}
      <div style={{background:t.card,border:`1px solid ${t.border}`,borderRadius:12,padding:20}}>
        <div style={{fontSize:13,fontWeight:700,marginBottom:12}}>System info</div>
        {[
          ["Model","SVM + Random Forest ensemble"],
          ["Training","1000+ labeled samples"],
          ["Backend","FastAPI + SQLite"],
          ["Version","CyberAI v2.0"],
        ].map(([k,v])=>(
          <div key={k} style={{display:"flex",justifyContent:"space-between",padding:"8px 0",borderBottom:`1px solid ${t.border}15`,fontSize:11}}>
            <span style={{color:t.textMuted}}>{k}</span>
            <span style={{fontFamily:"'Space Mono',monospace",color:t.accent}}>{v}</span>
          </div>
        ))}
      </div>

      <button onClick={onLogout}
        style={{width:"100%",padding:"10px",borderRadius:9,border:`1px solid ${t.high}33`,
          cursor:"pointer",background:t.highBg,color:t.high,fontWeight:700,fontSize:13,
          fontFamily:"'Syne',sans-serif",display:"flex",alignItems:"center",
          justifyContent:"center",gap:7}}>
        <Ico d={I.logout} s={15}/>Sign out
      </button>
    </div>
  );
}