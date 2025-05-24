document.addEventListener('DOMContentLoaded',function(){
  document.querySelectorAll('form').forEach(form=>{
    const btn=form.querySelector('button[type="submit"]'); if(!btn) return;
    const fields=Array.from(form.querySelectorAll('input,select')).filter(f=>f.type!=='hidden');
    const validate=()=>{ btn.disabled=!fields.every(f=>f.value.trim()); };
    fields.forEach(f=>f.addEventListener('input',validate)); validate();
  });
  console.log('UI scripts loaded');
});