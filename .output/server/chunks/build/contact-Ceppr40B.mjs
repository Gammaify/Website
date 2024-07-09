import { H as Head, T as Title } from './components-B1tENPZk.mjs';
import { withCtx, createTextVNode, createVNode, useSSRContext } from 'vue';
import { ssrRenderAttrs, ssrRenderComponent } from 'vue/server-renderer';
import { _ as _export_sfc } from './server.mjs';
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
import '../routes/renderer.mjs';
import 'vue-bundle-renderer/runtime';
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
              _push3(`Contact`);
            } else {
              return [createTextVNode("Contact")];
            }
          }),
          _: 1
        }, _parent2, _scopeId));
      } else {
        return [createVNode(_component_Title, null, {
          default: withCtx(() => [createTextVNode("Contact")]),
          _: 1
        })];
      }
    }),
    _: 1
  }, _parent));
  _push(`<h1>Contact</h1><form><div class="mb-4"><label>Your Name</label><input type="text" id="name" name="name" required></div><div class="mb-4"><label>Email</label><input type="email" id="email" name="email" required></div><div class="mb-4"><label>Subject</label><select name="subject" id="subject"><option value="General">General</option><option value="Web Development">Web Development</option><option value="Web Hosting">Web Hosting</option></select></div><div class="mb-4"><label>Message</label><textarea name="message" id="message" required></textarea></div></form></div>`);
}
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("pages/contact.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};
const contact = /* @__PURE__ */ _export_sfc(_sfc_main, [["ssrRender", _sfc_ssrRender]]);

export { contact as default };
//# sourceMappingURL=contact-Ceppr40B.mjs.map
