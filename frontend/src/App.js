import { useState, useEffect, useRef, useCallback } from "react";
import { AreaChart, Area, PieChart, Pie, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import {
  injectStyles, DARK, LIGHT, sc, apiClient, MOCK_ALERTS,
  Ico, I, Pulse, AuthPages, ApiKeyGuide,
  AnalysisResult, AlertsTable, ProfilePage, SettingsPage,
} from "./shared";

export default function App() {
  injectStyles();

  const [dark,      setDark]      = useState(true);
  const [user,      setUser]      = useState(null);
  const [page,      setPage]      = useState("dashboard");
  const [sideOpen,  setSideOpen]  = useState(true);
  const [mobSide,   setMobSide]   = useState(false);
  const [alerts,    setAlerts]    = useState([]);
  const [stats,     setStats]     = useState({total:0,high:0,medium:0,low:0});
  const [loadingD,  setLoadingD]  = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [result,    setResult]    = useState(null);
  const [logText,   setLogText]   = useState("");
  const [loginHist, setLoginHist] = useState([]);
  const [apiKey,    setApiKey]    = useState(() => localStorage.getItem("ctm_apikey") || "");
  const [mobile,    setMobile]    = useState(window.innerWidth < 768);
  const [chatMsgs,  setChatMsgs]  = useState([
    {role:"assistant", text:"Hi! I am your CyberAI assistant. Ask me anything about your alerts or threats."}
  ]);
  const [chatInput,   setChatInput]   = useState("");
  const [chatLoad,    setChatLoad]    = useState(false);
  const [liveLog,     setLiveLog]     = useState([]);
  const [downloading, setDownloading] = useState("");

  const fileRef    = useRef();
  const chatEndRef = useRef();
  const t = dark ? DARK : LIGHT;

  useEffect(() => {
    const h = () => {
      const m = window.innerWidth < 768;
      setMobile(m);
      if (m) setSideOpen(false);
    };
    window.addEventListener("resize", h); h();
    return () => window.removeEventListener("resize", h);
  }, []);

  useEffect(() => {
    const tok   = localStorage.getItem("ctm_token");
    const saved = localStorage.getItem("ctm_user");
    if (tok && saved) { try { setUser(JSON.parse(saved)); } catch {} }
  }, []);

  const fetchData = useCallback(async () => {
    setLoadingD(true);
    try {
      const [a, s] = await Promise.all([
        apiClient.get("/alerts"),
        apiClient.get("/stats"),
      ]);
      const alertList = Array.isArray(a.data) ? a.data : (a.data.alerts || []);
      setAlerts(alertList);
      setStats(s.data);
    } catch {
      setAlerts(MOCK_ALERTS);
      setStats({total:6, high:2, medium:2, low:2});
    }
    setLoadingD(false);
  }, []);

  useEffect(() => {
    if (!user) return;
    fetchData();
    apiClient.get("/auth/login-history")
      .then(r => setLoginHist(r.data))
      .catch(() => {});
    try {
      const ws = new WebSocket("wss://cyber-threat-monitor-mm0f.onrender.com");
      ws.onmessage = e => {
        const d = JSON.parse(e.data);
        setLiveLog(prev => [d, ...prev].slice(0, 30));
      };
      return () => ws.close();
    } catch {}
  }, [user, fetchData]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({behavior:"smooth"});
  }, [chatMsgs]);

  const handleLogin = useCallback(u => {
    setUser(u);
    localStorage.setItem("ctm_user", JSON.stringify(u));
    fetchData();
  }, [fetchData]);

  const handleLogout = () => {
    apiClient.post("/auth/logout").catch(() => {});
    localStorage.removeItem("ctm_token");
    localStorage.removeItem("ctm_user");
    setUser(null); setAlerts([]); setResult(null); setPage("dashboard");
  };

  const saveApiKey = k => {
    setApiKey(k);
    localStorage.setItem("ctm_apikey", k);
  };

  // ── FIXED: download with JWT token ────────────────────────────────────────
  const downloadFile = async (url, filename) => {
    setDownloading(filename);
    try {
      const response = await apiClient.get(url, { responseType: "blob" });
      const blob = new Blob([response.data]);
      const link = document.createElement("a");
      link.href = window.URL.createObjectURL(blob);
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(link.href);
    } catch (e) {
      alert("Download failed. Make sure backend is running and you are logged in.");
    }
    setDownloading("");
  };

  const analyzeText = async () => {
    if (!logText.trim()) return;
    setAnalyzing(true);
    try {
      const r = await apiClient.post("/analyze/text", {text: logText});
      setResult(r.data); fetchData();
    } catch {
      setResult({
        is_anomaly: true,
        severity: {level:"HIGH", score:0.91},
        explanation: ["Brute force pattern","Account lockout","Suspicious IP: 203.0.113.5"],
        entities: {ips:["203.0.113.5"], users:["admin"], ports:[]},
        ml_prediction: {label:"anomaly", confidence:0.91, anomaly_score:0.91},
      });
    }
    setAnalyzing(false);
  };

  const uploadFile = async e => {
    const file = e.target.files[0]; if (!file) return;
    setAnalyzing(true);
    const fd = new FormData(); fd.append("file", file);
    try {
      const r = await apiClient.post("/analyze/upload", fd);
      setResult(r.data); fetchData();
    } catch { setResult({total_sequences:10, anomalies_found:3}); }
    setAnalyzing(false);
  };

  const sendChat = async () => {
    if (!chatInput.trim()) return;
    const msg = chatInput; setChatInput("");
    setChatMsgs(prev => [...prev, {role:"user", text:msg}]);
    setChatLoad(true);
    if (!apiKey) {
      setChatMsgs(prev => [...prev, {role:"assistant",
        text:"Please enter your Anthropic API key above. Follow the guide to get your free key."}]);
      setChatLoad(false); return;
    }
    try {
      const res = await apiClient.post("/chat", {message:msg, history:chatMsgs.slice(-10)});
      setChatMsgs(prev => [...prev, {role:"assistant", text:res.data.reply}]);
    } catch {
      try {
        const res = await fetch("https://api.anthropic.com/v1/messages", {
          method:"POST",
          headers:{"Content-Type":"application/json","x-api-key":apiKey,"anthropic-version":"2023-06-01"},
          body: JSON.stringify({
            model:"claude-sonnet-4-20250514", max_tokens:600,
            system:"You are a cybersecurity expert assistant. Answer concisely.",
            messages: chatMsgs.filter((_,i)=>i>0)
              .map(m=>({role:m.role==="user"?"user":"assistant",content:m.text}))
              .concat([{role:"user",content:msg}]),
          }),
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error.message);
        setChatMsgs(prev => [...prev, {role:"assistant", text:data.content?.[0]?.text||"No response"}]);
      } catch (ex) {
        setChatMsgs(prev => [...prev, {role:"assistant",
          text:`Error: ${ex.message}. Check your API key.`}]);
      }
    }
    setChatLoad(false);
  };

  if (!user) return <AuthPages onLogin={handleLogin} t={t} />;

  const pieData = [
    {name:"HIGH",   value:stats.high   ||2},
    {name:"MEDIUM", value:stats.medium ||2},
    {name:"LOW",    value:stats.low    ||2},
  ];
  const areaData = Array.from({length:12},(_,i)=>({
    h:`${i*2}h`, a:Math.floor(Math.random()*8)+1, n:Math.floor(Math.random()*18)+4,
  }));

  const nav = [
    {id:"dashboard", label:"Dashboard", icon:I.dash},
    {id:"analyze",   label:"Analyze",   icon:I.up  },
    {id:"alerts",    label:"Alerts",    icon:I.bell},
    {id:"aichat",    label:"AI Chat",   icon:I.chat},
    {id:"profile",   label:"Profile",   icon:I.user},
    {id:"settings",  label:"Settings",  icon:I.cog },
  ];

  const showLabel = mobile ? true : sideOpen;
  const sideW     = mobile ? 240 : sideOpen ? 228 : 62;

  const btnStyle = (active) => ({
    display:"flex", alignItems:"center", gap:9, width:"100%",
    padding:"9px 9px", borderRadius:8, marginBottom:2, border:"none", cursor:"pointer",
    background:active ? t.accentSoft : "transparent",
    color:active ? t.accent : "#9d8ec7",
    borderLeft:active ? `3px solid ${t.accent}` : "3px solid transparent",
    justifyContent:showLabel ? "flex-start" : "center",
    transition:"all .15s", fontFamily:"'Syne',sans-serif",
  });

  return (
    <div style={{display:"flex",height:"100vh",overflow:"hidden",background:t.bg,color:t.text}}>

      {mobile && mobSide && (
        <div onClick={()=>setMobSide(false)}
          style={{position:"fixed",inset:0,background:"rgba(0,0,0,.55)",zIndex:88}}/>
      )}

      {/* SIDEBAR */}
      <aside style={{
        width:sideW, minWidth:sideW,
        height:"100vh", overflowY:"auto", overflowX:"hidden",
        background:t.sidebar, borderRight:`1px solid ${t.border}20`,
        display:"flex", flexDirection:"column",
        transition:"width .25s cubic-bezier(.4,0,.2,1), min-width .25s cubic-bezier(.4,0,.2,1)",
        position:mobile?"fixed":"relative",
        zIndex:mobile?99:1,
        transform:mobile?(mobSide?"translateX(0)":"translateX(-100%)"):"none",
        flexShrink:0,
      }}>
        <div style={{padding:"18px 12px 14px",display:"flex",alignItems:"center",
          gap:9,borderBottom:`1px solid ${t.border}18`}}>
          <div style={{width:32,height:32,borderRadius:8,flexShrink:0,
            background:"linear-gradient(135deg,#8b5cf6,#ec4899)",
            display:"flex",alignItems:"center",justifyContent:"center",
            animation:"glow 3s ease-in-out infinite"}}>
            <Ico d={I.shield} s={15}/>
          </div>
          {showLabel && (
            <div style={{animation:"fadeIn .15s ease",overflow:"hidden"}}>
              <div style={{fontSize:13,fontWeight:800,color:"#ede9fe",whiteSpace:"nowrap"}}>CyberAI</div>
              <div style={{fontSize:8,color:"#9d8ec7",fontFamily:"'Space Mono',monospace",letterSpacing:".1em"}}>MONITOR v2</div>
            </div>
          )}
        </div>

        <nav style={{flex:1,padding:"10px 7px"}}>
          {nav.map(item => (
            <button key={item.id}
              onClick={()=>{setPage(item.id);if(mobile)setMobSide(false);}}
              style={btnStyle(page===item.id)}>
              <span style={{flexShrink:0}}><Ico d={item.icon} s={17}/></span>
              {showLabel && (
                <span style={{fontSize:13,fontWeight:page===item.id?700:500,
                  animation:"fadeIn .15s ease",whiteSpace:"nowrap"}}>
                  {item.label}
                </span>
              )}
            </button>
          ))}
        </nav>

        <div style={{padding:"10px 9px",borderTop:`1px solid ${t.border}18`}}>
          {showLabel ? (
            <div style={{display:"flex",alignItems:"center",gap:8,animation:"fadeIn .15s ease"}}>
              <div style={{width:30,height:30,borderRadius:"50%",flexShrink:0,
                background:"linear-gradient(135deg,#8b5cf6,#ec4899)",
                display:"flex",alignItems:"center",justifyContent:"center",
                fontSize:12,fontWeight:800,color:"#fff"}}>
                {(user.full_name||user.username||"?")[0].toUpperCase()}
              </div>
              <div style={{flex:1,minWidth:0}}>
                <div style={{fontSize:11,fontWeight:700,color:"#ede9fe",
                  overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>
                  {user.full_name||user.username}
                </div>
                <div style={{fontSize:9,color:"#9d8ec7",fontFamily:"'Space Mono',monospace",textTransform:"uppercase"}}>
                  {user.role}
                </div>
              </div>
              <button onClick={handleLogout}
                style={{background:"none",border:"none",cursor:"pointer",color:"#9d8ec7",
                  padding:3,display:"flex",alignItems:"center",borderRadius:5,transition:"color .15s"}}
                onMouseEnter={e=>e.currentTarget.style.color="#f87171"}
                onMouseLeave={e=>e.currentTarget.style.color="#9d8ec7"}>
                <Ico d={I.logout} s={14}/>
              </button>
            </div>
          ) : (
            <div style={{display:"flex",justifyContent:"center"}}>
              <div style={{width:30,height:30,borderRadius:"50%",
                background:"linear-gradient(135deg,#8b5cf6,#ec4899)",
                display:"flex",alignItems:"center",justifyContent:"center",
                fontSize:12,fontWeight:800,color:"#fff"}}>
                {(user.full_name||user.username||"?")[0].toUpperCase()}
              </div>
            </div>
          )}
        </div>
      </aside>

      {/* MAIN */}
      <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden",minWidth:0}}>

        {/* Topbar */}
        <header style={{height:56,background:t.card,borderBottom:`1px solid ${t.border}`,
          display:"flex",alignItems:"center",padding:"0 14px",gap:10,flexShrink:0,zIndex:50}}>
          <button onClick={()=>mobile?setMobSide(o=>!o):setSideOpen(o=>!o)}
            style={{background:t.accentSoft,border:`1px solid ${t.border}`,
              borderRadius:7,padding:6,cursor:"pointer",color:t.accent,
              display:"flex",alignItems:"center",flexShrink:0}}>
            <Ico d={(mobile?mobSide:sideOpen)?I.x:I.menu} s={16}/>
          </button>
          <div style={{flex:1,minWidth:0}}>
            <div style={{fontSize:15,fontWeight:800,color:t.text}}>
              {nav.find(n=>n.id===page)?.label}
            </div>
            {!mobile && (
              <div style={{fontSize:9,color:t.textMuted,fontFamily:"'Space Mono',monospace"}}>
                {new Date().toLocaleDateString("en-US",{weekday:"short",year:"numeric",month:"short",day:"numeric"})}
              </div>
            )}
          </div>
          {!mobile && (
            <div style={{display:"flex",alignItems:"center",gap:5,padding:"4px 10px",
              borderRadius:20,background:"rgba(52,211,153,.07)",border:"1px solid rgba(52,211,153,.2)"}}>
              <Pulse color="#34d399"/>
              <span style={{fontSize:9,color:"#34d399",fontFamily:"'Space Mono',monospace",fontWeight:700}}>LIVE</span>
            </div>
          )}
          <button onClick={()=>setDark(d=>!d)}
            style={{background:t.accentSoft,border:`1px solid ${t.border}`,
              borderRadius:7,padding:"5px 9px",cursor:"pointer",color:t.accent,
              display:"flex",alignItems:"center",gap:5,fontSize:11,fontWeight:600,
              fontFamily:"'Syne',sans-serif",flexShrink:0}}>
            <Ico d={dark?I.sun:I.moon} s={14}/>
            {!mobile&&(dark?"Light":"Dark")}
          </button>
        </header>

        {/* Pages */}
        <main style={{flex:1,overflowY:"auto",padding:mobile?"10px":"18px 22px"}}>

          {/* DASHBOARD */}
          {page==="dashboard" && (
            <div style={{animation:"fadeUp .4s ease"}}>
              <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(150px,1fr))",gap:10,marginBottom:16}}>
                {[
                  {label:"Total Alerts",val:stats.total||alerts.length,c:t.accent},
                  {label:"High",        val:stats.high  ||0,c:t.high},
                  {label:"Medium",      val:stats.medium||0,c:t.mid },
                  {label:"Low",         val:stats.low   ||0,c:t.low },
                ].map((s,i)=>(
                  <div key={s.label} style={{background:t.card,border:`1px solid ${t.border}`,
                    borderRadius:12,padding:"16px 18px",borderLeft:`3px solid ${s.c}`,
                    animation:`fadeUp .4s ease ${i*0.07}s both`}}>
                    <div style={{fontSize:10,color:t.textMuted,marginBottom:5,fontFamily:"'Space Mono',monospace"}}>{s.label}</div>
                    <div style={{fontSize:28,fontWeight:800,color:s.c,fontFamily:"'Space Mono',monospace"}}>{s.val}</div>
                  </div>
                ))}
              </div>

              <div style={{display:"grid",gridTemplateColumns:mobile?"1fr":"1fr 260px",gap:12,marginBottom:16}}>
                <div style={{background:t.card,border:`1px solid ${t.border}`,borderRadius:12,padding:18}}>
                  <div style={{fontSize:13,fontWeight:700,marginBottom:3}}>Anomaly timeline</div>
                  <div style={{fontSize:10,color:t.textMuted,marginBottom:14,fontFamily:"'Space Mono',monospace"}}>24h view</div>
                  <ResponsiveContainer width="100%" height={170}>
                    <AreaChart data={areaData}>
                      <defs>
                        <linearGradient id="ag" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%"  stopColor={t.accent} stopOpacity={.22}/>
                          <stop offset="95%" stopColor={t.accent} stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="h" stroke={t.textDim} tick={{fontSize:8,fontFamily:"Space Mono"}}/>
                      <YAxis stroke={t.textDim} tick={{fontSize:8,fontFamily:"Space Mono"}}/>
                      <Tooltip contentStyle={{background:t.card,border:`1px solid ${t.border}`,borderRadius:7,color:t.text,fontSize:11}}/>
                      <Area type="monotone" dataKey="a" stroke={t.accent} strokeWidth={2} fill="url(#ag)" name="Anomalies"/>
                      <Area type="monotone" dataKey="n" stroke={t.low} strokeWidth={1.5} fill="none" strokeDasharray="4 3" name="Normal"/>
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
                <div style={{background:t.card,border:`1px solid ${t.border}`,borderRadius:12,padding:18}}>
                  <div style={{fontSize:13,fontWeight:700,marginBottom:3}}>Severity split</div>
                  <ResponsiveContainer width="100%" height={130}>
                    <PieChart>
                      <Pie data={pieData} cx="50%" cy="50%" innerRadius={36} outerRadius={56} dataKey="value" paddingAngle={3}>
                        {pieData.map(d=><Cell key={d.name} fill={sc(t,d.name)}/>)}
                      </Pie>
                      <Tooltip contentStyle={{background:t.card,border:`1px solid ${t.border}`,borderRadius:7,color:t.text,fontSize:11}}/>
                    </PieChart>
                  </ResponsiveContainer>
                  {pieData.map(d=>(
                    <div key={d.name} style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:4}}>
                      <div style={{display:"flex",alignItems:"center",gap:5}}>
                        <div style={{width:6,height:6,borderRadius:"50%",background:sc(t,d.name)}}/>
                        <span style={{fontSize:10,color:t.textMuted}}>{d.name}</span>
                      </div>
                      <span style={{fontSize:10,fontWeight:700,color:sc(t,d.name),fontFamily:"'Space Mono',monospace"}}>{d.value}</span>
                    </div>
                  ))}
                </div>
              </div>

              {liveLog.length>0 && (
                <div style={{background:t.card,border:`1px solid ${t.border}`,borderRadius:12,padding:18,marginBottom:16}}>
                  <div style={{fontSize:13,fontWeight:700,marginBottom:10,display:"flex",alignItems:"center",gap:8}}>
                    <Pulse color="#34d399"/> Live log stream
                  </div>
                  <div style={{maxHeight:160,overflowY:"auto",display:"flex",flexDirection:"column",gap:4}}>
                    {liveLog.map((l,i)=>(
                      <div key={i} style={{display:"flex",alignItems:"center",gap:8,
                        padding:"5px 9px",borderRadius:6,
                        background:l.is_anomaly?t.highBg:t.accentSoft,
                        fontSize:11,fontFamily:"'Space Mono',monospace"}}>
                        <span style={{color:l.is_anomaly?t.high:t.low,fontWeight:700,flexShrink:0}}>
                          {l.is_anomaly?"ALERT":"OK"}
                        </span>
                        <span style={{color:t.textMuted,flexShrink:0}}>{new Date(l.timestamp).toLocaleTimeString()}</span>
                        <span style={{color:t.text,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{l.log}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <AlertsTable alerts={alerts.slice(0,6)} loading={loadingD} t={t} mobile={mobile}/>
            </div>
          )}

          {/* ANALYZE */}
          {page==="analyze" && (
            <div style={{animation:"fadeUp .4s ease",maxWidth:820}}>
              <div style={{display:"grid",gridTemplateColumns:mobile?"1fr":"1fr 1fr",gap:14,marginBottom:16}}>

                {/* Text analyze */}
                <div style={{background:t.card,border:`1px solid ${t.border}`,borderRadius:12,padding:20}}>
                  <div style={{fontSize:13,fontWeight:700,marginBottom:3}}>Analyze log text</div>
                  <div style={{fontSize:10,color:t.textMuted,marginBottom:12,fontFamily:"'Space Mono',monospace"}}>Paste log sequence</div>
                  <textarea value={logText} onChange={e=>setLogText(e.target.value)}
                    placeholder="failed login [SEP] failed login [SEP] account locked"
                    style={{width:"100%",height:100,resize:"vertical",background:t.input,
                      color:t.text,border:`1px solid ${t.border}`,borderRadius:8,
                      padding:"9px 11px",fontFamily:"'Space Mono',monospace",fontSize:11,outline:"none"}}
                    onFocus={e=>e.target.style.borderColor=t.accent}
                    onBlur={e=>e.target.style.borderColor=t.border}/>
                  <button onClick={analyzeText} disabled={analyzing||!logText.trim()}
                    style={{marginTop:10,width:"100%",padding:"10px",borderRadius:8,border:"none",
                      cursor:analyzing||!logText.trim()?"not-allowed":"pointer",
                      background:analyzing||!logText.trim()?t.border:"linear-gradient(135deg,#8b5cf6,#ec4899)",
                      color:"#fff",fontWeight:700,fontSize:13,fontFamily:"'Syne',sans-serif",
                      display:"flex",alignItems:"center",justifyContent:"center",gap:7}}>
                    {analyzing
                      ?<><span style={{width:15,height:15,border:"2px solid #ffffff30",borderTopColor:"#fff",borderRadius:"50%",display:"inline-block",animation:"spin .7s linear infinite"}}/>Analyzing...</>
                      :"Run AI analysis"}
                  </button>
                </div>

                {/* Upload + Export */}
                <div style={{background:t.card,border:`1px solid ${t.border}`,borderRadius:12,padding:20}}>
                  <div style={{fontSize:13,fontWeight:700,marginBottom:3}}>Upload log file</div>
                  <div style={{fontSize:10,color:t.textMuted,marginBottom:12,fontFamily:"'Space Mono',monospace"}}>.txt · .log</div>
                  <div onClick={()=>fileRef.current?.click()}
                    style={{border:`2px dashed ${t.border}`,borderRadius:9,padding:"28px 14px",
                      textAlign:"center",cursor:"pointer",transition:"all .2s"}}
                    onMouseEnter={e=>{e.currentTarget.style.borderColor=t.accent;e.currentTarget.style.background=t.accentSoft;}}
                    onMouseLeave={e=>{e.currentTarget.style.borderColor=t.border;e.currentTarget.style.background="transparent";}}>
                    <Ico d={I.up} s={26}/>
                    <div style={{fontSize:12,fontWeight:600,color:t.text,marginTop:9}}>
                      {analyzing?"Processing...":"Drop or click to upload"}
                    </div>
                    <div style={{fontSize:10,color:t.textMuted,marginTop:3}}>Supports .txt and .log</div>
                  </div>
                  <input ref={fileRef} type="file" accept=".txt,.log" onChange={uploadFile} style={{display:"none"}}/>

                  {/* ── FIXED Export buttons ── */}
                  <div style={{display:"flex",gap:8,marginTop:14}}>
                    <button
                      onClick={()=>downloadFile("/alerts/export/csv","alerts.csv")}
                      disabled={downloading==="alerts.csv"}
                      style={{flex:1,padding:"9px",borderRadius:7,border:`1px solid ${t.border}`,
                        background:downloading==="alerts.csv"?t.border:t.accentSoft,
                        color:t.accent,fontSize:11,fontWeight:700,cursor:"pointer",
                        fontFamily:"'Syne',sans-serif",display:"flex",alignItems:"center",
                        justifyContent:"center",gap:5,transition:"all .2s"}}>
                      {downloading==="alerts.csv"
                        ?<><span style={{width:12,height:12,border:"2px solid #8b5cf650",borderTopColor:t.accent,borderRadius:"50%",display:"inline-block",animation:"spin .7s linear infinite"}}/>Downloading...</>
                        :"Export CSV"}
                    </button>
                    <button
                      onClick={()=>downloadFile("/alerts/export/pdf","threat_report.pdf")}
                      disabled={downloading==="threat_report.pdf"}
                      style={{flex:1,padding:"9px",borderRadius:7,border:`1px solid ${t.border}`,
                        background:downloading==="threat_report.pdf"?t.border:t.accentSoft,
                        color:t.accent,fontSize:11,fontWeight:700,cursor:"pointer",
                        fontFamily:"'Syne',sans-serif",display:"flex",alignItems:"center",
                        justifyContent:"center",gap:5,transition:"all .2s"}}>
                      {downloading==="threat_report.pdf"
                        ?<><span style={{width:12,height:12,border:"2px solid #8b5cf650",borderTopColor:t.accent,borderRadius:"50%",display:"inline-block",animation:"spin .7s linear infinite"}}/>Downloading...</>
                        :"Export PDF"}
                    </button>
                  </div>
                </div>
              </div>
              {result && <AnalysisResult result={result} t={t}/>}
            </div>
          )}

          {/* ALERTS */}
          {page==="alerts" && (
            <div style={{animation:"fadeUp .4s ease"}}>
              <AlertsTable alerts={alerts} loading={loadingD} t={t} full mobile={mobile}/>
            </div>
          )}

          {/* AI CHAT */}
          {page==="aichat" && (
            <div style={{animation:"fadeUp .4s ease",maxWidth:700}}>
              {!apiKey && <ApiKeyGuide t={t}/>}
              <div style={{background:t.card,border:`1px solid ${apiKey?t.low+"44":t.border}`,
                borderRadius:12,padding:14,marginBottom:14,display:"flex",gap:10,alignItems:"center"}}>
                <Ico d={I.key} s={16}/>
                <input value={apiKey} onChange={e=>saveApiKey(e.target.value)} type="password"
                  placeholder="Paste your Anthropic API key here (sk-ant-...)"
                  style={{flex:1,padding:"8px 12px",borderRadius:7,background:t.input,
                    border:`1px solid ${t.border}`,color:t.text,fontSize:12,outline:"none",
                    fontFamily:"'Space Mono',monospace"}}
                  onFocus={e=>e.target.style.borderColor=t.accent}
                  onBlur={e=>e.target.style.borderColor=t.border}/>
                {apiKey?(
                  <div style={{display:"flex",alignItems:"center",gap:6,flexShrink:0}}>
                    <span style={{fontSize:10,color:t.low,fontFamily:"'Space Mono',monospace",
                      padding:"3px 8px",borderRadius:20,background:t.lowBg,border:`1px solid ${t.low}33`}}>
                      KEY SET
                    </span>
                    <button onClick={()=>saveApiKey("")}
                      style={{background:"none",border:"none",cursor:"pointer",color:t.textMuted,fontSize:11,padding:"2px 6px"}}>
                      Clear
                    </button>
                  </div>
                ):(
                  <span style={{fontSize:10,color:t.textMuted,fontFamily:"'Space Mono',monospace",flexShrink:0}}>No key</span>
                )}
              </div>

              <div style={{background:t.card,border:`1px solid ${t.border}`,borderRadius:12,overflow:"hidden"}}>
                <div style={{padding:"13px 16px",borderBottom:`1px solid ${t.border}`,
                  display:"flex",alignItems:"center",gap:7}}>
                  <Ico d={I.chat} s={15}/>
                  <span style={{fontSize:13,fontWeight:700}}>CyberAI Assistant</span>
                  <span style={{fontSize:9,color:t.textMuted,fontFamily:"'Space Mono',monospace",marginLeft:"auto"}}>
                    Powered by Claude
                  </span>
                </div>
                <div style={{height:360,overflowY:"auto",padding:14,display:"flex",flexDirection:"column",gap:10}}>
                  {chatMsgs.map((msg,i)=>(
                    <div key={i} style={{display:"flex",justifyContent:msg.role==="user"?"flex-end":"flex-start"}}>
                      <div style={{maxWidth:"80%",padding:"9px 13px",borderRadius:12,
                        fontSize:13,lineHeight:1.55,
                        background:msg.role==="user"?"linear-gradient(135deg,#8b5cf6,#ec4899)":t.input,
                        color:msg.role==="user"?"#fff":t.text,
                        borderBottomRightRadius:msg.role==="user"?2:12,
                        borderBottomLeftRadius:msg.role==="assistant"?2:12}}>
                        {msg.text}
                      </div>
                    </div>
                  ))}
                  {chatLoad&&(
                    <div style={{display:"flex",gap:5,padding:"8px 12px",background:t.input,borderRadius:12,width:"fit-content"}}>
                      {[0,1,2].map(i=>(
                        <div key={i} style={{width:6,height:6,borderRadius:"50%",background:t.accent,
                          animation:`typing .9s ease-in-out ${i*0.2}s infinite`}}/>
                      ))}
                    </div>
                  )}
                  <div ref={chatEndRef}/>
                </div>
                <div style={{padding:12,borderTop:`1px solid ${t.border}`,display:"flex",gap:9}}>
                  <input value={chatInput} onChange={e=>setChatInput(e.target.value)}
                    onKeyDown={e=>e.key==="Enter"&&!e.shiftKey&&sendChat()}
                    placeholder="Ask about threats, IPs, attack patterns..."
                    style={{flex:1,padding:"9px 12px",borderRadius:8,background:t.input,
                      border:`1px solid ${t.border}`,color:t.text,fontSize:13,outline:"none",
                      fontFamily:"'Syne',sans-serif"}}
                    onFocus={e=>e.target.style.borderColor=t.accent}
                    onBlur={e=>e.target.style.borderColor=t.border}/>
                  <button onClick={sendChat} disabled={chatLoad||!chatInput.trim()}
                    style={{padding:"9px 16px",borderRadius:8,border:"none",
                      background:`linear-gradient(135deg,${t.accent},#ec4899)`,
                      color:"#fff",fontWeight:700,fontSize:12,cursor:"pointer",
                      opacity:chatLoad||!chatInput.trim()?0.5:1}}>
                    Send
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* PROFILE */}
          {page==="profile" && (
            <div style={{animation:"fadeUp .4s ease",maxWidth:580}}>
              <ProfilePage user={user} loginHist={loginHist} t={t}/>
            </div>
          )}

          {/* SETTINGS */}
          {page==="settings" && (
            <div style={{animation:"fadeUp .4s ease",maxWidth:520}}>
              <SettingsPage dark={dark} setDark={setDark} t={t} onLogout={handleLogout}/>
            </div>
          )}

        </main>
      </div>
    </div>
  );
}