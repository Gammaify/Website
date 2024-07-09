import { H as Head, T as Title } from './components-B1tENPZk.mjs';
import { withCtx, createTextVNode, createVNode, useSSRContext } from 'vue';
import { ssrRenderAttrs, ssrRenderComponent, ssrRenderAttr } from 'vue/server-renderer';
import { _ as _imports_0 } from './virtual_public-DcBoMN6N.mjs';
import { _ as _export_sfc } from './server.mjs';
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

const _sfc_main = {};
function _sfc_ssrRender(_ctx, _push, _parent, _attrs) {
  const _component_Head = Head;
  const _component_Title = Title;
  _push(`<div${ssrRenderAttrs(_attrs)}>`);
  _push(ssrRenderComponent(_component_Head, null, {
    default: withCtx((_, _push2, _parent2, _scopeId) => {
      if (_push2) {
        _push2(ssrRenderComponent(_component_Title, null, {
          default: withCtx((_2, _push3, _parent3, _scopeId2) => {
            if (_push3) {
              _push3(`About`);
            } else {
              return [createTextVNode("About")];
            }
          }),
          _: 1
        }, _parent2, _scopeId));
      } else {
        return [createVNode(_component_Title, null, {
          default: withCtx(() => [createTextVNode("About")]),
          _: 1
        })];
      }
    }),
    _: 1
  }, _parent));
  _push(`<h1 class="text-center text-3xl p-5">About</h1><div class="mx-auto w-4/5 md:w-3/5 lg:w-3/5 xl:w-1/3 pb-8"><img class="rounded-full borderColor border-4"${ssrRenderAttr("src", _imports_0)} alt="Picture of Me"></div><p class="pb-4">Welcome to my corner of the web!</p><p class="pb-4">I\u2019m Oliver Smith, a dedicated website developer with over five years of experience in crafting dynamic and user-friendly websites. My expertise spans across a range of technologies, including HTML, CSS, JavaScript, C#, and TypeScript. With a passion for coding and a commitment to deliver high-quality, responsive websites tailored to meet the unique needs of each client.</p><p class="pb-4">My mission is to empower businesses by creating bespoke websites that are not only visually appealing but also functionally robust. I believe that a great website should not only look good but also provide a seamless user experience, which is why I focus on both design and functionality.</p><h4 class="text-2xl text-center pb-4">My Services</h4><ul class="list-disc pl-10"><li class="pt-2 pb-2">Custom Website Development: Whether you need a brand-new website or a redesign of your existing site, I bring your vision to life with custom solutions.</li><li class="pt-2 pb-2">Responsive Design: I ensure your website looks and performs great on all devices, from desktops to smartphones.</li><li class="pt-2 pb-2">E-commerce Solutions: I build secure and scalable e-commerce platforms that help you sell online with ease. My best solution for e-commerce is Shopify.</li><li class="pt-2 pb-2">Web Applications: Leveraging my expertise in C# and TypeScript, Building robust backend systems and applications that support your business logic.</li><li class="pt-2 pb-2">Maintenance and Support: My services don\u2019t end at launch. I provide ongoing maintenance and support to keep your website running smoothly.</li></ul></div>`);
}
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("pages/about.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};
const about = /* @__PURE__ */ _export_sfc(_sfc_main, [["ssrRender", _sfc_ssrRender]]);

export { about as default };
//# sourceMappingURL=about-etcnR3mu.mjs.map
