import { H as Head, T as Title } from './components-B1tENPZk.mjs';
import { useSSRContext, defineComponent, withCtx, createTextVNode, createVNode, mergeProps } from 'vue';
import { ssrRenderAttrs, ssrRenderComponent, ssrRenderAttr, ssrInterpolate } from 'vue/server-renderer';
import { _ as _imports_0 } from './virtual_public-DcBoMN6N.mjs';
import { a as _sfc_main$4 } from './server.mjs';
import '../routes/renderer.mjs';
import 'vue-bundle-renderer/runtime';
import '../runtime.mjs';
import 'node:http';
import 'node:https';
import 'lru-cache';
import 'fs';
import 'path';
import 'cron';
import 'nodemailer';
import 'sqlstring';
import 'net';
import 'tls';
import 'timers';
import 'events';
import 'stream';
import 'denque';
import 'buffer';
import 'long';
import 'iconv-lite';
import 'process';
import 'crypto';
import 'zlib';
import 'seq-queue';
import 'generate-function';
import 'url';
import 'named-placeholders';
import 'node:crypto';
import 'node:fs';
import 'node:url';
import 'xss';
import 'devalue';
import '@unhead/ssr';
import 'unhead';
import '@unhead/shared';
import 'vue-router';

const _sfc_main$2 = /* @__PURE__ */ defineComponent({
  __name: "LinkIcon",
  __ssrInlineRender: true,
  props: {
    Link: String
  },
  setup(__props) {
    const props = __props;
    return (_ctx, _push, _parent, _attrs) => {
      if (__props.Link != "") {
        _push(`<div${ssrRenderAttrs(_attrs)}><a target="_blank"${ssrRenderAttr("href", props.Link)}><svg class="h-8 w-8 textPrimaryColor hover:animate-jump" width="24" height="24" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z"></path> <path d="M11 7h-5a2 2 0 0 0 -2 2v9a2 2 0 0 0 2 2h9a2 2 0 0 0 2 -2v-5"></path> <line x1="10" y1="14" x2="20" y2="4"></line> <polyline points="15 4 20 4 20 9"></polyline></svg></a></div>`);
      } else {
        _push(`<!---->`);
      }
    };
  }
});
const _sfc_setup$2 = _sfc_main$2.setup;
_sfc_main$2.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/icons/LinkIcon.vue");
  return _sfc_setup$2 ? _sfc_setup$2(props, ctx) : void 0;
};
const _sfc_main$1 = /* @__PURE__ */ defineComponent({
  __name: "PortfolioCard",
  __ssrInlineRender: true,
  props: {
    ImageURL: String,
    GitHubLink: String,
    ProjectName: String,
    WebsiteLink: String
  },
  setup(__props) {
    const props = __props;
    return (_ctx, _push, _parent, _attrs) => {
      _push(`<div${ssrRenderAttrs(mergeProps({
        class: "border-solid border-2 borderColor rounded p-2"
      }, _attrs))}>`);
      if (props.WebsiteLink != "") {
        _push(`<a target="_blank"${ssrRenderAttr("href", props.WebsiteLink)}><img${ssrRenderAttr("src", props.ImageURL)}></a>`);
      } else {
        _push(`<img${ssrRenderAttr("src", props.ImageURL)}>`);
      }
      _push(`<h4 class="p-2 text-center text-xl lg:text-base">${ssrInterpolate(props.ProjectName)}</h4><div class="flex justify-between">`);
      _push(ssrRenderComponent(_sfc_main$2, {
        Link: props.WebsiteLink
      }, null, _parent));
      _push(ssrRenderComponent(_sfc_main$4, {
        Link: props.GitHubLink
      }, null, _parent));
      _push(`</div></div>`);
    };
  }
});
const _sfc_setup$1 = _sfc_main$1.setup;
_sfc_main$1.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/PortfolioCard.vue");
  return _sfc_setup$1 ? _sfc_setup$1(props, ctx) : void 0;
};
const _sfc_main = /* @__PURE__ */ defineComponent({
  __name: "index",
  __ssrInlineRender: true,
  setup(__props) {
    return (_ctx, _push, _parent, _attrs) => {
      const _component_Head = Head;
      const _component_Title = Title;
      _push(`<div${ssrRenderAttrs(_attrs)}>`);
      _push(ssrRenderComponent(_component_Head, null, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(ssrRenderComponent(_component_Title, null, {
              default: withCtx((_2, _push3, _parent3, _scopeId2) => {
                if (_push3) {
                  _push3(`Home`);
                } else {
                  return [createTextVNode("Home")];
                }
              }),
              _: 1
            }, _parent2, _scopeId));
          } else {
            return [createVNode(_component_Title, null, {
              default: withCtx(() => [createTextVNode("Home")]),
              _: 1
            })];
          }
        }),
        _: 1
      }, _parent));
      _push(`<div class="mx-auto w-4/5 md:w-3/5 lg:w-3/5 xl:w-1/3"><img class="rounded-full borderColor border-4"${ssrRenderAttr("src", _imports_0)} alt="Picture of Me"><h1 class="pt-4 text-center text-xl">Hey there! My name&#39;s Oliver Smith, and welcome to Gammaify, your one-stop shop for all things website gamification!</h1></div><h2 class="text-center text-3xl p-5 mt-5 border-solid border-t-2 borderColor" id="portfolio">Portfolio</h2><div class="grid lg:grid-cols-3 md:grid-cols-2 gap-4">`);
      _push(ssrRenderComponent(_sfc_main$1, {
        ImageURL: "/images/gingerfoxSite.png",
        ProjectName: "Ginger Fox",
        GitHubLink: "https://github.com/Gammaify/GingerFoxTheme",
        WebsiteLink: "https://www.gingerfox.co.uk"
      }, null, _parent));
      _push(ssrRenderComponent(_sfc_main$1, {
        ImageURL: "/images/traitorsDigitalGame.png",
        ProjectName: "Traitors Digital Game",
        GitHubLink: "https://github.com/Gammaify/TraitorsDigitalGame",
        WebsiteLink: "https://www.thetraitors.tv/g/traitors-card-game/index.html"
      }, null, _parent));
      _push(ssrRenderComponent(_sfc_main$1, {
        ImageURL: "/images/catchphraseMicrosite.png",
        ProjectName: "Catchphrase Micro-site",
        GitHubLink: "https://github.com/Gammaify/CatchphraseMicrosite",
        WebsiteLink: "https://www.catchphrasecardgame.com/"
      }, null, _parent));
      _push(ssrRenderComponent(_sfc_main$1, {
        ImageURL: "/images/popmasterMicrosite.png",
        ProjectName: "Popmaster Micro-site",
        GitHubLink: "https://github.com/Gammaify/PopmasterMicrosite",
        WebsiteLink: "https://www.popmastergame.co.uk/board-game"
      }, null, _parent));
      _push(ssrRenderComponent(_sfc_main$1, {
        ImageURL: "/images/TraitorsMicrosite.png",
        ProjectName: "Traitors Micro-site",
        GitHubLink: "https://github.com/Gammaify/TraitorsMicrosite",
        WebsiteLink: "https://www.thetraitorscardgame.co.uk/"
      }, null, _parent));
      _push(ssrRenderComponent(_sfc_main$1, {
        ImageURL: "/images/tapSite.png",
        ProjectName: "The Admin Practice",
        GitHubLink: "https://github.com/Gammaify/TheAdminPractice",
        WebsiteLink: ""
      }, null, _parent));
      _push(`</div></div>`);
    };
  }
});
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("pages/index.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};

export { _sfc_main as default };
//# sourceMappingURL=index-w-BgH8pP.mjs.map
