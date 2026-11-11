"""Execute the real payment UI functions, including mobile error focus and retries."""
import json
import subprocess
import unittest
from pathlib import Path


class TestDebtPaymentFeedback(unittest.TestCase):
    def test_open_uses_fresh_outstanding_debts_and_handles_load_failure(self):
        source = Path(__file__).with_name('web_server.py').read_text(encoding='utf-8')
        start = source.index('    function populatePayDebtSelects(')
        end = source.index('    function applyPresetPayDebt(', start)
        program = r'''
const vm=require('vm'),assert=require('assert');
const nodes={};
class Node {
  constructor(){this.children=[];this.disabled=false;this._value='';this.classList={remove(){}};}
  set innerHTML(v){this.children=[];this._value=''}
  appendChild(v){this.children.push(v)}
  replaceChildren(){this.children=[];this._value=''}
  get value(){return this.children.length?(this.children.find(x=>x.selected)||this.children[0]).value:this._value}
  set value(v){this._value=v;if(this.children.length){this.children.forEach(c=>c.selected=c.value===v);if(!this.children.some(c=>c.selected))this.children=[]}}
}
const node=id=>nodes[id]??=new Node();
let payload={debts:[{id:'closed',name:'Closed',debt_rub:'0.00'},
 {id:'open',name:'Outstanding',debt_rub:'175000.00'},
 {id:'other',name:'Other',debt_rub:'500.00'}]};
const ctx={document:{getElementById:node,createElement:()=>({})},
 allDebtsData:{debts:[{id:'stale',debt_rub:'10.00'}]},
 overviewData:{accounts:[{id:'cash',type:'ASSET',subtype:'CASH',balance_rub:'5000'}]},categoryData:null,
 authHeaders:()=>({}),updatePayDebtForecast(){},onDebtLiabilityChanged(){},
 applyPresetPayDebt(amount,percent){ctx.preset={amount,percent}},showPayDebtError(m){ctx.error=m},
 fetch:async()=>({ok:true,json:async()=>payload})};
vm.createContext(ctx);vm.runInContext(JSON.parse(process.argv[1]),ctx);
(async()=>{
 await ctx.openPayDebtModal();
 assert.equal(node('payDebtLiabilityAccount').value,'open');
 assert.equal(node('payDebtLiabilityAccount').children.length,2);
 assert.equal(ctx.preset.percent,100);assert(!node('btnSubmitPayDebt').disabled);
 await ctx.openPayDebtModal('other','25.00');
 assert.equal(node('payDebtLiabilityAccount').value,'other');assert.equal(ctx.preset.amount,'25.00');
 await ctx.openPayDebtModal('closed');
 assert(node('btnSubmitPayDebt').disabled);assert.equal(node('payDebtLiabilityAccount').value,'');
 assert(ctx.error.includes('недоступен'));
 payload={debts:[{id:'closed',debt_rub:'0.00'}]};await ctx.openPayDebtModal();
 assert(node('btnSubmitPayDebt').disabled);assert(ctx.error.includes('остатком'));
 ctx.fetch=async()=>{throw Error('Offline')};await ctx.openPayDebtModal();
 assert(node('btnSubmitPayDebt').disabled);assert(ctx.error.includes('Offline'));
 let release;ctx.fetch=()=>new Promise(r=>release=r);
 const pending=ctx.openPayDebtModal();
 vm.runInContext('++payDebtOpenSequence',ctx);
 release({ok:true,json:async()=>({debts:[{id:'late',debt_rub:'99'}]})});await pending;
 assert.equal(node('payDebtLiabilityAccount').children.length,0);
})().catch(e=>{console.error(e);process.exitCode=1});
'''
        result = subprocess.run(['node', '-e', program, json.dumps(source[start:end])],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_errors_are_visible_and_pending_submit_cannot_repeat(self):
        source = Path(__file__).with_name('web_server.py').read_text(encoding='utf-8')
        start = source.index('    function showPayDebtError(')
        end = source.index('    async function loadEnvelopes()', start)
        program = r'''
const vm = require('vm'), assert = require('assert');
const functions = JSON.parse(process.argv[1]);
function fixture() {
  const nodes = {};
  const node = id => nodes[id] ??= {value:'', textContent:'Pay', disabled:false,
    replaceChildren(child){this.child=child}, focus(){this.focused=true},
    scrollIntoView(){this.scrolled=true},setAttribute(){},removeAttribute(){}};
  node('payDebtLiabilityAccount').value='debt';
  node('payDebtSourceAccount').value='cash';
  node('payDebtAmount').value='100';
  node('payDebtAmountPercent').value='100';
  node('payDebtDesc').value='Payment';
  const ctx = {document:{getElementById:node,createElement:()=>({style:{}})},
    authHeaders:()=>({}),parseFloat,closePayDebtModal(){ctx.closed=true},
    async loadDashboard(){},async loadDebts(){},async loadTransactions(){},currentSelectedMonth:''};
  vm.createContext(ctx);vm.runInContext(functions,ctx);
  return {ctx,node};
}
(async()=>{
  const f=fixture(); let calls=0, release;
  f.ctx.fetch=()=>{calls++;return new Promise(r=>release=r)};
  const first=f.ctx.submitPayDebt();
  assert.equal(f.node('btnSubmitPayDebt').disabled,true);
  await f.ctx.submitPayDebt();assert.equal(calls,1);
  release({ok:false,json:async()=>({status:'error',message:'Insufficient funds'})});await first;
  const box=f.node('payDebtMsg');assert(box.focused&&box.scrolled);
  assert(box.child.textContent.includes('Insufficient funds'));
  assert.equal(f.node('btnSubmitPayDebt').disabled,false);assert(!f.ctx.closed);
  f.ctx.fetch=async()=>{throw Error('Connection lost')};await f.ctx.submitPayDebt();
  assert(box.child.textContent.includes('Connection lost'));assert(!f.node('btnSubmitPayDebt').disabled);
  f.ctx.fetch=async()=>({ok:true,json:async()=>({status:'success'})});await f.ctx.submitPayDebt();
  assert(f.ctx.closed);assert(!f.node('btnSubmitPayDebt').disabled);
  const v=fixture();v.node('payDebtAmount').value='0';
  v.ctx.fetch=()=>{throw Error('validation must not send')};await v.ctx.submitPayDebt();
  assert(v.node('payDebtMsg').focused&&v.node('payDebtMsg').scrolled);
})().catch(e=>{console.error(e);process.exitCode=1});
'''
        result = subprocess.run(['node', '-e', program, json.dumps(source[start:end])],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
