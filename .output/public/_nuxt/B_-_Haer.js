import{T as d,H as g}from"./DX-xIt76.js";import{_ as p}from"./CDNRLhYq.js";import{f as c,o as a,c as r,e as i,g as _,b as u,t as k,a as e,h as b,w as l,d as f}from"./CAI-sonL.js";const L={key:0},x=["href"],w=u('<svg class="h-8 w-8 textPrimaryColor hover:animate-jump" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z"></path> <path d="M11 7h-5a2 2 0 0 0 -2 2v9a2 2 0 0 0 2 2h9a2 2 0 0 0 2 -2v-5"></path> <line x1="10" y1="14" x2="20" y2="4"></line> <polyline points="15 4 20 4 20 9"></polyline></svg>',1),y=[w],G=c({__name:"LinkIcon",props:{Link:String},setup(s){const t=s;return(m,n)=>s.Link!=""?(a(),r("div",L,[i("a",{target:"_blank",href:t.Link},y,8,x)])):_("",!0)}}),P={class:"border-solid border-2 borderColor rounded p-2"},v=["href"],H=["src"],M=["src"],N={class:"p-2 text-center text-xl lg:text-base"},T={class:"flex justify-between"},o=c({__name:"PortfolioCard",props:{ImageURL:String,GitHubLink:String,ProjectName:String,WebsiteLink:String},setup(s){const t=s;return(m,n)=>(a(),r("div",P,[t.WebsiteLink!=""?(a(),r("a",{key:0,target:"_blank",href:t.WebsiteLink},[i("img",{src:t.ImageURL},null,8,H)],8,v)):(a(),r("img",{key:1,src:t.ImageURL},null,8,M)),i("h4",N,k(t.ProjectName),1),i("div",T,[e(G,{Link:t.WebsiteLink},null,8,["Link"]),e(b,{Link:t.GitHubLink},null,8,["Link"])])]))}}),j=i("div",{class:"mx-auto w-4/5 md:w-3/5 lg:w-3/5 xl:w-1/3"},[i("img",{class:"rounded-full borderColor border-4",src:p,alt:"Picture of Me"}),i("h1",{class:"pt-4 text-center text-xl"},"Hey there! My name's Oliver Smith, and welcome to Gammaify, your one-stop shop for all things website gamification!")],-1),C=i("h2",{class:"text-center text-3xl p-5 mt-5 border-solid border-t-2 borderColor",id:"portfolio"},"Portfolio",-1),I={class:"grid lg:grid-cols-3 md:grid-cols-2 gap-4"},R=c({__name:"index",setup(s){return(t,m)=>{const n=d,h=g;return a(),r("div",null,[e(h,null,{default:l(()=>[e(n,null,{default:l(()=>[f("Home")]),_:1})]),_:1}),j,C,i("div",I,[e(o,{ImageURL:"/images/gingerfoxSite.png",ProjectName:"Ginger Fox",GitHubLink:"https://github.com/Gammaify/GingerFoxTheme",WebsiteLink:"https://www.gingerfox.co.uk"}),e(o,{ImageURL:"/images/traitorsDigitalGame.png",ProjectName:"Traitors Digital Game",GitHubLink:"https://github.com/Gammaify/TraitorsDigitalGame",WebsiteLink:"https://www.thetraitors.tv/g/traitors-card-game/index.html"}),e(o,{ImageURL:"/images/catchphraseMicrosite.png",ProjectName:"Catchphrase Micro-site",GitHubLink:"https://github.com/Gammaify/CatchphraseMicrosite",WebsiteLink:"https://www.catchphrasecardgame.com/"}),e(o,{ImageURL:"/images/popmasterMicrosite.png",ProjectName:"Popmaster Micro-site",GitHubLink:"https://github.com/Gammaify/PopmasterMicrosite",WebsiteLink:"https://www.popmastergame.co.uk/board-game"}),e(o,{ImageURL:"/images/TraitorsMicrosite.png",ProjectName:"Traitors Micro-site",GitHubLink:"https://github.com/Gammaify/TraitorsMicrosite",WebsiteLink:"https://www.thetraitorscardgame.co.uk/"}),e(o,{ImageURL:"/images/tapSite.png",ProjectName:"The Admin Practice",GitHubLink:"https://github.com/Gammaify/TheAdminPractice",WebsiteLink:""})])])}}});export{R as default};