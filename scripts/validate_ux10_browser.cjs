/* Run with an existing Playwright installation; all API traffic is intercepted. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require(process.env.UX_BROWSER_MODULE || "playwright");
const base = process.env.UX_BASE_URL || "http://127.0.0.1:3001";
const output = process.env.UX_BROWSER_OUTPUT || "/tmp/ux10-browser";
const stamp = "2026-09-06T12:00:00Z";
const routes = [
  ["/settings/detection-control", "Detection Control Plane"],
  ["/network-events", "Network Activity"],
  ["/dns-telemetry", "DNS Telemetry"],
  ["/system-information/operation-history", "Operation History"],
];
const readyHeadings = {
  "/settings/detection-control":"Configuration Versioning",
  "/network-events":"Network event filters",
  "/dns-telemetry":"DNS event filters",
  "/system-information/operation-history":"Filters",
};
const diff = {
  added: [], removed: [], unchanged_count: 1,
  modified: [{rule_id:"managed-1", name:"Fixture managed entry", changes:{reason:{from:"Before",to:"After"}}}],
  summary: {added_count:0,removed_count:0,modified_count:1},
};
const validation = {valid:true,severity:"OK",messages:[],warnings:[],requires_restart:true,affected_services:["ai-soc-worker"]};
const managed = {
  id:"managed-1",name:"Fixture managed entry",type:"NOISE_SUPPRESSION",status:"ACTIVE",
  scope:"host:fixture",matcher_kind:"CONTAINS",matcher_value:"service status",reason:"Fixture only",
  owner:"SOC",enabled:true,description:"Isolated browser fixture",created_at:stamp,updated_at:stamp,
  created_by:"fixture",updated_by:"fixture",last_validation_status:null,last_validation_message:null,
  requires_apply:true,affected_service:"ai-soc-worker",restart_note:"Governed restart",metadata:{},
};
const inventoryItem = {
  id:"native-1",name:"Fixture native rule",type:"DETECTION_RULE",source:"WAZUH",scope:"host:fixture",
  target:"fixture",status:"ACTIVE",managed:false,requires_reload:false,last_seen:stamp,
  description:"Native inventory",reason:"Fixture",metadata:{rule_id:"100001"},
};
const states = ["DRAFT","PROPOSED","APPROVED","ACTIVE","DISABLED","SUPERSEDED","FAILED_VALIDATION","REJECTED","ROLLED_BACK"];
const lifecycle = states.map((state,i) => ({
  id:i+1,policy_type:"NOISE_SUPPRESSION",rule_key:"fixture-"+state,title:"Fixture "+state,
  version_number:1,state,created_by_user_id:2,created_by_username:"fixture",updated_by_username:"fixture",
  content_json:{source:"wazuh",match:{host:"fixture",rule_group:"pam,sudo"},action:"suppress",scope:"specific_host"},
  validation_status:state==="FAILED_VALIDATION"?"failed":"passed",
  validation_errors:state==="FAILED_VALIDATION"?[{field:"scope",message:"Fixture blocking finding"}]:[],
  validation_warnings:[],expires_at:"2026-12-01",owner:"SOC",business_reason:"Fixture only",
  source_system:"WAZUH",config_domain:"noise_suppression",restart_recommended:true,
  affected_services:["ai-soc-worker"],allowed_transitions:[],created_at:stamp,updated_at:stamp,
}));
const operation = {
  ...managed,id:"lifecycle:4",source:"lifecycle",native_id:4,rule_key:"fixture-active",version_number:1,
  state:"ACTIVE",active:true,scope_classification:"dangerously_broad",scope_reasons:["Fixture broad scope"],
  source_system:"WAZUH",validation_status:"passed",validation_errors:[],validation_warnings:[],
  hit_count:7,hit_count_source:"stored_counter",last_match_at:stamp,config_domain:"noise_suppression",
  affected_services:["ai-soc-worker"],restart_recommended:true,review_status:"review_due",review_due:true,
  expired:false,expires_at:"2026-12-01",review_notes:"Fixture review",metadata:{content_json:{match:{host:"fixture"}}},
};
const opSummary = {
  total:1,active:1,inactive:0,review_due:1,expired:0,validation_failed:0,
  scope:{dangerously_broad:1,broad:0},types:{NOISE_SUPPRESSION:1},statuses:{ACTIVE:1},
  stored_hit_count:7,last_match_at:stamp,affected_services:["ai-soc-worker"],
};
const eventMatch = {source_table:"raw_events",id:1,source:"WAZUH",timestamp:stamp,agent:"fixture",
  rule_id:"100001",rule_description:"Fixture service",level:3,event_count:1,payload_preview:"service status fixture"};
const service = {
  key:"ai_soc_worker",display_name:"AI SOC Worker",description:"Fixture worker",kind:"systemd",risk_level:"high",
  restart_allowed:true,restart_disabled_reason:null,requires_admin:true,impact:"May interrupt fixture processing",
  post_restart_check:"Worker heartbeat",command_family:"systemd",unit:"ai-soc-worker",container:null,
  status:"running",status_details:null,last_operation:null,
};
const historyItem = {operation_id:1,service_key:service.key,display_name:service.display_name,
  operation_type:"restart_preview",action:"restart_preview",status:"success",reason:"Fixture history",
  requested_by_username:"fixture",related_config_version_id:2,pre_status:"running",post_status:"running",
  safe_message:"Preview completed",safe_error:null,created_at:stamp,started_at:stamp,finished_at:stamp};
function version(domain,number=2) {
  return {id:number,config_domain:domain,version_number:number,status:number===2?"ACTIVE":"SUPERSEDED",
    config_checksum:"fixture-checksum",checksum_short:"fixture",created_at:stamp,created_by:"fixture",
    created_reason:"Fixture reason",activated_at:stamp,activated_by:"fixture",validation_status:"OK",
    validation_errors:[],validation_warnings:[],diff_summary:diff,rollback_of_version_id:null,
    requires_restart:true,affected_services:["ai-soc-worker"],config_payload:{items:[managed]}};
}
const networkEvent = {id:1,event_type:"alert",source:"suricata",event_timestamp:stamp,src_ip:"192.0.2.1",
  src_port:12345,dest_ip:"198.51.100.1",dest_port:443,proto:"TCP",app_proto:"tls",hostname:"fixture.example",
  tls_sni:"fixture.example",url:"https://fixture.example/path",alert_signature:"Fixture IDS alert",
  alert_category:"Fixture category",alert_severity:3};
const dnsEvent = {id:1,source:"wazuh",event_timestamp:stamp,agent_name:"fixture",client_ip:"192.0.2.1",
  resolver_ip:"198.51.100.53",query_name:"fixture.example",query_type:"A",collector:"endpoint",raw_line:"fixture DNS A query"};

async function fixture(browser, role="ADMIN", mode="normal", width=1440) {
  const context = await browser.newContext({viewport:{width,height:1000}});
  const user = {id:role==="ADMIN"?1:role==="ANALYST"?2:3,username:"fixture",role,is_active:true};
  await context.addCookies([{name:"ai_soc_access_token",value:"ux10-fixture",url:base}]);
  await context.addInitScript(user => {
    localStorage.setItem("ai_soc_access_token","ux10-fixture");
    localStorage.setItem("ai_soc_user",JSON.stringify(user));
  }, user);
  const requests = [], unexpected = [], errors = [];
  const control = {invalid:false,previewAllowed:true,restartFailed:false};
  const page = await context.newPage();
  page.on("pageerror", e => errors.push(e.message));
  // Fail closed: no API request, including an unknown mutation, reaches a server.
  await context.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin !== new URL(base).origin) {
      unexpected.push(request.url()); return route.abort();
    }
    if (!url.pathname.startsWith("/api-backend/")) {
      if (request.method() !== "GET" && !url.pathname.startsWith("/_next/")) {
        unexpected.push(request.method()+" "+url.pathname); return route.abort();
      }
      return route.continue();
    }
    const p = url.pathname.slice("/api-backend".length), method = request.method();
    const body = request.postData() ? JSON.parse(request.postData()) : null;
    requests.push({p,method,query:url.search,body});
    const send = (value,status=200) => route.fulfill({status,contentType:"application/json",body:JSON.stringify(value)});
    if (p==="/auth/me") return send(user);
    if (mode==="slow") await new Promise(r=>setTimeout(r,1800));
    if (mode==="error") return send({detail:"Fixture backend unavailable"},503);
    if (mode==="forbidden") return send({detail:"Fixture authorization denied"},403);
    const empty = mode==="empty";
    if (p==="/settings/detection-control") return send({
      summary:{total_items:1,total_rules:1,active_rules:1,disabled_rules:0,exceptions:0,telemetry_sources:0,
        policies:0,service_controls:0,managed_items:0,unmanaged_items:1,pending_review:0,read_only:true,generated_at:stamp},
      rules:empty?[]:[inventoryItem],exceptions:[],telemetry_sources:[],policies:[],service_controls:[],
    });
    if (p==="/detection-control/rules" && method==="GET") return send({
      items:empty?[]:[managed],summary:{total:empty?0:1,active:1,disabled:0,failed_validation:0,generated_at:stamp,
        restart_orchestration:"governed"},rbac:{role,can_write:role==="ADMIN"}});
    if (p.startsWith("/detection-control/rules") && method!=="GET") {
      return send(method==="DELETE"?{archived:true}:{rule:{...managed,...body},validation});
    }
    const config=p.match(/^\/detection-control\/config-versions\/([^/]+)(?:\/(.+))?$/);
    if (config) {
      const [,domain,action] = config;
      if (!action) return send({items:empty?[]:[version(domain),version(domain,1)],domains:[domain]});
      if (action==="active") return send(empty?null:version(domain));
      if (/^\d+$/.test(action)) return send(version(domain,Number(action)));
      if (action==="validate") return send(control.invalid
        ? {...validation,valid:false,severity:"OK",messages:["Fixture validation failed"],warnings:[]}:validation);
      if (action==="diff") return send(diff);
      if (["apply","rollback"].includes(action)) return send({version:version(domain,3),validation,diff});
    }
    if (p==="/detection-control/semantic-context") return send({enabled:true,status:"available",
      similar_detection_controls:[],similar_case_closures:[],similar_historical_incidents:[],related_playbooks:[],
      warnings:[],result_count:0,decision_boundary:"Advisory only",message:"Fixture advisory"});
    if (p==="/detection-control/lifecycle/items" && method==="GET") return send({
      items:empty?[]:lifecycle,summary:{total:empty?0:9,validation_failed:1,restart_recommended:1,states:{}},
      states,policy_types:["NOISE_SUPPRESSION","EXCEPTION","DETECTION_RULE"],source_systems:["WAZUH"],
    });
    const life=p.match(/^\/detection-control\/lifecycle\/items(?:\/(\d+)(?:\/(.+))?)?$/);
    if (life) {
      const item=lifecycle[Number(life[1]||1)-1], action=life[2];
      if (action==="history") return send({item_id:item.id,events:[{id:1,timestamp:stamp,actor:"fixture",
        actor_role:role,action:"created",from_state:null,to_state:item.state,comment:"Fixture audit",details:{}}]});
      if (action==="diff") return send(diff);
      if (method==="DELETE") return send({deleted:true});
      return send({item: action==="validate" && control.invalid ? {...item,validation_status:"failed"}:item,
        validation:{valid:!control.invalid,validation_status:control.invalid?"failed":"passed",
          errors:control.invalid?[{field:"scope",message:"Fixture blocking finding"}]:[],warnings:[]},
        message:"Fixture "+(action||"draft saved")});
    }
    if (p==="/detection-control/operations/overview") return send({summary:opSummary,active_summary:opSummary,
      top_review_items:[],rbac:{role,can_preview:role!=="VIEWER",can_review:role!=="VIEWER",can_admin:role==="ADMIN"},generated_at:stamp});
    if (/\/operations\/(noise-suppression|exceptions|rules)$/.test(p)) return send({
      items:empty?[]:[operation],summary:opSummary,available_filters:{status:[],scope_classification:[],review_status:[]},generated_at:stamp});
    if (p.endsWith("/matched-events")) return send({item:operation,matches:[eventMatch],observed_count:1,
      scan_limit:1000,count_source:"recent_event_scan",generated_at:stamp});
    if (p.endsWith("/match-preview")) return send({preview:{scope_classification:{classification:"dangerously_broad",
      reasons:["Fixture broad scope"]},observed_count:1,scan_limit:1000,count_source:"recent_event_scan"},matches:[eventMatch],generated_at:stamp});
    if (/\/(mark-reviewed|extend-review)$/.test(p)) return send({item:{...operation,...body}});
    if (p==="/service-operations/services") return send({services:empty?[]:[service],supported_statuses:["running"]});
    if (p.endsWith("/restart-preview")) return send({service_key:service.key,display_name:service.display_name,
      allowed:control.previewAllowed,risk_level:"high",current_status:"running",requires_confirmation:true,reason_required:true,
      impact:service.impact,post_restart_check:service.post_restart_check,command_family:"systemd",
      warnings:control.previewAllowed?["Fixture high-impact service"]:["Fixture preview blocked"],operation:historyItem});
    if (p.endsWith("/restart")) return send({operation_id:2,service_key:service.key,action:"restart",
      status:control.restartFailed?"failed":"success",pre_status:"running",post_status:control.restartFailed?"failed":"running",
      message:control.restartFailed?"Fixture restart failed":"Fixture restart succeeded",safe_error:control.restartFailed?"Fixture failure":null});
    if (p.endsWith("/status")) return send({status:"running",operation:historyItem});
    if (p==="/service-operations/operations") {
      const offset=Number(url.searchParams.get("offset")||0);
      return send({items:empty?[]:[{...historyItem,operation_id:offset+1}],total:empty?0:51,
        limit:Number(url.searchParams.get("limit")||25),offset,page:offset/25+1,total_pages:empty?1:3});
    }
    if (p==="/network-events/summary") return send({total:empty?0:1,by_event_type:empty?[]:[{event_type:"alert",count:1}],
      top_destinations:empty?[]:[{dest_ip:"198.51.100.1",count:1,country:"Unknown",resolver_context:{is_observed_resolver:false}}],
      top_hostnames:empty?[]:[{hostname:"fixture.example",count:1}],latest_event_timestamp:empty?null:stamp});
    if (p==="/network-events") return send({items:empty?[]:[networkEvent],total:empty?0:1,limit:100,offset:0});
    if (p==="/dns-events/summary") return send({total:empty?0:1,latest_event:empty?null:dnsEvent,
      latest_event_freshness_seconds:empty?null:120,by_query_type:empty?[]:[{query_type:"A",count:1}],
      top_domains:empty?[]:[{query_name:"fixture.example",count:1}],top_clients:empty?[]:[{client:"fixture",count:1}]});
    if (p==="/dns-events") return send({items:empty?[]:[dnsEvent],total:empty?0:1,limit:100,offset:0});
    unexpected.push(method+" "+p); return send({detail:"Unmapped fixture"},501);
  });
  async function open(route=routes[0][0]) {
    await page.goto(base+route);
    await page.getByRole("heading",{level:1}).waitFor();
    if (mode==="normal"||mode==="empty") {
      await page.getByRole("heading",{name:readyHeadings[route],exact:true}).waitFor();
      await page.waitForFunction(()=>!Array.from(document.querySelectorAll('[role="status"]'))
        .some(e=>e.textContent.trim().startsWith("Loading")));
    }
  }
  async function check(label) {
    assert.deepEqual(errors,[],label+" JavaScript errors");
    assert.deepEqual(unexpected,[],label+" unmapped network");
    const fits=await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1);
    if (!fits) {
      await page.screenshot({path:path.join(output,"overflow.png"),fullPage:true});
      console.error(await page.locator("body *").evaluateAll(nodes=>nodes
        .filter(e=>e.getBoundingClientRect().right>innerWidth+1 && getComputedStyle(e).position!=="fixed")
        .slice(0,12).map(e=>({tag:e.tagName,class:e.className,width:e.getBoundingClientRect().width}))));
    }
    assert.equal(fits,true,label+" overflow");
  }
  return {page,context,requests,control,open,check};
}
const section=(page,title)=>page.getByRole("heading",{name:title,exact:true}).locator("xpath=ancestor::section[1]");
const enabled=async (locator,value)=>assert.equal(await locator.isEnabled(),value,await locator.getAttribute("aria-label")||await locator.textContent());
async function response(page,action,suffix) {
  const wait=page.waitForResponse(r=>new URL(r.url()).pathname.endsWith(suffix));
  await action(); await wait; await page.waitForTimeout(120);
}
async function run() {
  fs.mkdirSync(output,{recursive:true});
  const browser=await chromium.launch({headless:true,executablePath:process.env.UX_BROWSER_EXECUTABLE});
  const results=[];
  try {
    for (const width of [390,1440,1920]) {
      const f=await fixture(browser,"ADMIN","normal",width);
      for (const [route,title] of routes) {
        await f.open(route); await f.check(title+" "+width);
        await f.page.screenshot({path:path.join(output,route.replaceAll("/","_")+"-"+width+".png"),fullPage:true});
        results.push(title+" "+width+" PASS");
      }
      await f.context.close();
    }
    for (const role of ["ADMIN","ANALYST","VIEWER"]) {
      const f=await fixture(browser,role); const {page,control,requests}=f;
      await f.open();
      const config=section(page,"Configuration Versioning");
      await enabled(config.getByRole("button",{name:"Validate",exact:true}),role!=="VIEWER");
      await enabled(config.getByRole("button",{name:"Apply version",exact:true}),false);
      const services=section(page,"Managed Service Restart");
      await enabled(services.getByRole("button",{name:"Restart",exact:true}),role==="ADMIN");
      assert.equal(await page.getByRole("link",{name:/^Observability/}).count(),role==="VIEWER"?0:1);
      const ops=section(page,"Exceptions and Noise Operations");
      await ops.getByRole("button",{name:"View details",exact:true}).click();
      await enabled(ops.getByRole("button",{name:"Preview",exact:true}),role!=="VIEWER");
      await enabled(ops.getByRole("button",{name:"Mark",exact:true}),role!=="VIEWER");
      const life=section(page,"Detection Lifecycle");
      await life.getByRole("button",{name:"Open",exact:true}).click();
      await life.getByRole("table").waitFor();
      const row=state=>life.getByRole("row").filter({hasText:"Fixture "+state}).first();
      for (const state of states) {
        const buttons=row(state).getByRole("button");
        assert.ok(await buttons.count()>0);
        const has=name=>row(state).getByRole("button",{name,exact:true}).count();
        assert.equal(await has("Apply"),Number(role==="ADMIN" && state==="APPROVED"));
        assert.equal(await has("Disable"),Number(role==="ADMIN" && state==="ACTIVE"));
        assert.equal(await has("Approve"),Number(role==="ADMIN" && state==="PROPOSED"));
        assert.equal(await has("Reject"),Number(role==="ADMIN" && ["PROPOSED","APPROVED"].includes(state)));
        assert.equal(await has("Validate"),Number(role!=="VIEWER" && ["DRAFT","PROPOSED","FAILED_VALIDATION"].includes(state)));
        assert.equal(await has("Submit"),Number(role!=="VIEWER" && ["DRAFT","FAILED_VALIDATION"].includes(state)));
        assert.equal(await has("Return to draft"),Number(role!=="VIEWER" && ["PROPOSED","FAILED_VALIDATION","REJECTED","DISABLED"].includes(state)));
        assert.equal(await has("Clone"),Number(role!=="VIEWER" && ["REJECTED","DISABLED","ACTIVE","SUPERSEDED"].includes(state)));
        assert.equal(await has("Edit"),Number(role!=="VIEWER" && ["DRAFT","FAILED_VALIDATION"].includes(state)));
        assert.equal(await has("Delete draft"),Number(role!=="VIEWER" && state==="DRAFT"));
      }
      if (role!=="VIEWER") {
        control.invalid=true;
        await response(page,()=>config.getByRole("button",{name:"Validate",exact:true}).click(),"/validate");
        assert.ok((await config.textContent()).includes("blocked / OK"));
        assert.equal(await config.getByText("blocked / OK",{exact:true}).evaluate(e=>e.className.includes("text-red")),true);
        await response(page,()=>row("DRAFT").getByRole("button",{name:"Validate",exact:true}).click(),"/validate");
        await life.getByText("Validation failed. Review the blocking findings.",{exact:true}).waitFor();
        await response(page,()=>ops.getByRole("button",{name:"Preview",exact:true}).click(),"/match-preview");
        await ops.getByText("Preview / expected matches",{exact:true}).waitFor();
        control.invalid=false;
        await response(page,()=>config.getByRole("button",{name:"Validate",exact:true}).click(),"/validate");
        await response(page,()=>config.getByRole("button",{name:"Preview diff",exact:true}).click(),"/diff");
        await enabled(config.getByRole("button",{name:"Apply version",exact:true}),role==="ADMIN");
        await config.getByText("Raw diff / technical changes",{exact:true}).click();
        assert.ok((await config.locator("pre").textContent()).includes('"from": "Before"'));
      }
      if (role==="ADMIN") {
        let mutationCount=requests.filter(r=>/\/(apply|rollback|restart)$/.test(r.p)).length;
        page.once("dialog",d=>d.dismiss());
        await config.getByRole("button",{name:"Apply version",exact:true}).click();
        page.once("dialog",d=>d.dismiss());
        await config.getByRole("button",{name:"Rollback",exact:true}).click();
        assert.equal(requests.filter(r=>/\/(apply|rollback|restart)$/.test(r.p)).length,mutationCount);
        const cancelConfirmation=async dialog=>dialog.type()==="prompt"
          ? dialog.accept("Fixture-only reason") : dialog.dismiss();
        page.on("dialog",cancelConfirmation);
        await config.getByRole("button",{name:"Apply version",exact:true}).click();
        await config.getByRole("button",{name:"Rollback",exact:true}).click();
        page.off("dialog",cancelConfirmation);
        assert.equal(requests.filter(r=>/\/(apply|rollback|restart)$/.test(r.p)).length,mutationCount);
        const managedTable=section(page,"Managed Control Entries");
        await managedTable.getByRole("button",{name:"Archive",exact:true}).click();
        await page.getByRole("dialog",{name:"Archive managed entry"}).waitFor();
        await page.keyboard.press("Escape");
        assert.equal(requests.filter(r=>r.method==="DELETE").length,0);
        await row("DRAFT").getByRole("button",{name:"Delete draft",exact:true}).click();
        await page.getByRole("dialog",{name:"Delete lifecycle draft"}).getByRole("button",{name:"Cancel",exact:true}).click();
        assert.equal(requests.filter(r=>r.method==="DELETE").length,0);
        await services.getByRole("button",{name:"Restart",exact:true}).click();
        const dialog=page.getByRole("dialog",{name:"Restart AI SOC Worker",exact:true});
        await enabled(dialog.getByRole("button",{name:"Run preview",exact:true}),false);
        await enabled(dialog.getByRole("button",{name:"Restart service",exact:true}),false);
        await dialog.getByRole("textbox",{name:"Reason (required)",exact:true}).fill("Fixture-only maintenance");
        await response(page,()=>dialog.getByRole("button",{name:"Run preview",exact:true}).click(),"/restart-preview");
        await enabled(dialog.getByRole("button",{name:"Restart service",exact:true}),false);
        assert.equal(requests.filter(r=>r.p.endsWith("/restart")).length,0);
        await dialog.getByRole("checkbox").check();
        await enabled(dialog.getByRole("button",{name:"Restart service",exact:true}),true);
        await dialog.getByRole("textbox",{name:"Reason (required)",exact:true}).fill("Changed fixture reason");
        await enabled(dialog.getByRole("button",{name:"Restart service",exact:true}),false);
        assert.equal(await dialog.getByRole("checkbox").isChecked(),false);
        control.previewAllowed=false;
        await response(page,()=>dialog.getByRole("button",{name:"Run preview",exact:true}).click(),"/restart-preview");
        await dialog.getByRole("checkbox").check();
        await enabled(dialog.getByRole("button",{name:"Restart service",exact:true}),false);
        control.previewAllowed=true;
        await response(page,()=>dialog.getByRole("button",{name:"Run preview",exact:true}).click(),"/restart-preview");
        control.restartFailed=true;
        await response(page,()=>dialog.getByRole("button",{name:"Restart service",exact:true}).click(),"/restart");
        await dialog.getByText("Fixture restart failed",{exact:true}).waitFor();
        assert.equal(requests.find(r=>r.p.endsWith("/restart")).body.confirm,true);
        assert.equal(requests.find(r=>r.p.endsWith("/restart")).body.reason,"Changed fixture reason");
        await dialog.getByRole("button",{name:"Cancel",exact:true}).click();
        await services.getByRole("button",{name:"Restart",exact:true}).click();
        assert.equal(await dialog.getByRole("textbox",{name:"Reason (required)",exact:true}).inputValue(),"");
        await page.keyboard.press("Escape");
        await dialog.waitFor({state:"hidden"});
      }
      await f.check(role);
      await page.screenshot({path:path.join(output,"controls-"+role+".png"),fullPage:true});
      results.push(role+" permission, validation, transition and safety controls PASS");
      await f.context.close();
    }
    {
      const f=await fixture(browser,"ADMIN","normal",390);
      await f.open();
      await section(f.page,"Detection Lifecycle").getByRole("button",{name:"Open",exact:true}).click();
      await f.check("Mobile expanded lifecycle");
      await section(f.page,"Managed Service Restart").getByRole("button",{name:"Restart",exact:true}).click();
      const dialog=f.page.getByRole("dialog",{name:"Restart AI SOC Worker",exact:true});
      for (let i=0;i<8;i++) {
        await f.page.keyboard.press("Tab");
        // Native dialogs allow browser-chrome focus, but not background controls.
        assert.equal(await f.page.evaluate(()=>!document.hasFocus() || Boolean(document.activeElement.closest("dialog"))),true,"Modal keyboard focus");
      }
      await dialog.getByRole("textbox",{name:"Reason (required)",exact:true}).fill("Mobile fixture");
      await response(f.page,()=>dialog.getByRole("button",{name:"Run preview",exact:true}).click(),"/restart-preview");
      await dialog.getByRole("checkbox").check();
      await enabled(dialog.getByRole("button",{name:"Restart service",exact:true}),true);
      await f.page.screenshot({path:path.join(output,"mobile-restart-dialog.png")});
      await f.check("Mobile restart dialog");
      await f.page.keyboard.press("Escape");
      assert.equal(f.requests.filter(r=>r.p.endsWith("/restart")).length,0);
      await f.context.close();
      results.push("Mobile expanded lifecycle, restart preview, keyboard focus and Escape PASS");
    }
    for (const mode of ["empty","error","forbidden","slow"]) {
      const f=await fixture(browser,"ADMIN",mode);
      for (const [route,title] of routes) {
        await f.open(route);
        if (mode==="slow") await f.page.getByRole("status").filter({hasText:/Loading/}).first().waitFor();
        else if (mode==="error"||mode==="forbidden") await f.page.getByRole("alert").filter({hasText:/failed|Unable/}).first().waitFor();
        else assert.ok((await f.page.textContent("body")).match(/No managed entries|No network events|No DNS events|No matching service/));
        await f.check(mode+" "+title);
        results.push(mode+" "+title+" PASS");
      }
      await f.context.close();
    }
    const f=await fixture(browser);
    await f.open("/network-events");
    await f.page.getByRole("combobox",{name:"Event type",exact:true}).selectOption("tls");
    await f.page.getByLabel("Source IP",{exact:true}).fill("192.0.2.2");
    await f.page.getByLabel("Hostname",{exact:true}).fill("fixture.example");
    await f.page.getByRole("button",{name:"Clear",exact:true}).click();
    assert.equal(await f.page.getByLabel("Source IP",{exact:true}).inputValue(),"");
    await f.open("/dns-telemetry");
    await f.page.getByRole("combobox",{name:"Query type",exact:true}).selectOption("AAAA");
    await f.page.getByLabel("Domain contains",{exact:true}).fill("fixture.example");
    await f.page.getByRole("button",{name:"Reset",exact:true}).click();
    assert.equal(await f.page.getByLabel("Domain contains",{exact:true}).inputValue(),"");
    await f.open("/system-information/operation-history");
    await f.page.getByRole("button",{name:"Next",exact:true}).click();
    await f.page.getByText(/Page 2 of 3/).waitFor();
    await f.page.getByLabel("Search operation history",{exact:true}).fill("fixture");
    await f.page.waitForTimeout(500);
    assert.ok(f.requests.some(r=>r.query.includes("search=fixture")));
    await f.page.getByRole("button",{name:"Reset",exact:true}).click();
    await f.check("filters/history");
    await f.context.close();
    results.push("Telemetry filters/reset and history pagination/search PASS");
    fs.writeFileSync(path.join(output,"results.json"),JSON.stringify(results,null,2));
    console.log(results.join("\n"));
  } finally { await browser.close(); }
}
module.exports = {fixture, section, routes};
if (require.main === module) run().catch(error=>{console.error(error);process.exitCode=1;});
