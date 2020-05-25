
'use strict';

$('.progress-bar').css('width', '100%');

// POST key form
$('#addKey form').submit(async e => {
  e.preventDefault();
  $('#addKey .alert').addClass('hidden');
  $('#addKey .progress').removeClass('hidden');
  const publicKeyArmored = $('#addKey textarea').val();
  try {
    const response = await fetch('/api/v1/key', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({publicKeyArmored})});
    const responseText = await response.text();
    if (!response.ok) {
      return alert('addKey', 'danger', responseText);
    }
    alert('addKey', 'success', responseText);
  } catch (e) {
    console.log('Fetch error', e);
    alert('addKey', 'danger', 'Network did not respond');
  }
});

// DELETE key form
$('#removeKey form').submit(async e => {
  e.preventDefault();
  $('#removeKey .alert').addClass('hidden');
  $('#removeKey .progress').removeClass('hidden');
  const email = $('#removeKey input[type="email"]').val();
  try {
    const response = await fetch(`/api/v1/key?email=${encodeURIComponent(email)}`, {method: 'DELETE'});
    const responseText = await response.text();
    if (!response.ok) {
      return alert('removeKey', 'danger', responseText);
    }
    alert('removeKey', 'success', responseText);
  } catch (e) {
    console.log('Fetch error', e);
    alert('removeKey', 'danger', 'Network did not respond');
  }
});

function alert(region, outcome, text) {
  $(`#${region} .progress`).addClass('hidden');
  $(`#${region} .alert-${outcome} span`).text(text);
  $(`#${region} .alert-${outcome}`).removeClass('hidden');
}
