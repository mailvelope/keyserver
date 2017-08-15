/* eslint strict: 0 */
/* global jQuery */

(function($) {
  'use strict';

  $('.progress-bar').css('width', '100%');

  // POST key form
  $('#addKey form').submit(e => {
    e.preventDefault();
    $('#addKey .alert').addClass('hidden');
    $('#addKey .progress').removeClass('hidden');
    $.ajax({
      method: 'POST',
      url: '/api/v1/key',
      data: JSON.stringify({publicKeyArmored: $('#addKey textarea').val()}),
      contentType: 'application/json',
    }).done((data, textStatus, xhr) => {
      if (xhr.status === 304) {
        alert('addKey', 'danger', 'Key already exists!');
      } else {
        alert('addKey', 'success', xhr.responseText);
      }
    })
    .fail(xhr => {
      alert('addKey', 'danger', xhr.responseText);
    });
  });

  // DELETE key form
  $('#removeKey form').submit(e => {
    e.preventDefault();
    $('#removeKey .alert').addClass('hidden');
    $('#removeKey .progress').removeClass('hidden');
    const email = $('#removeKey input[type="email"]').val();
    $.ajax({
      method: 'DELETE',
      url: `/api/v1/key?email=${encodeURIComponent(email)}`
    }).done((data, textStatus, xhr) => {
      alert('removeKey', 'success', xhr.responseText);
    })
    .fail(xhr => {
      alert('removeKey', 'danger', xhr.responseText);
    });
  });

  function alert(region, outcome, text) {
    $(`#${region} .progress`).addClass('hidden');
    $(`#${region} .alert-${outcome} span`).text(text);
    $(`#${region} .alert-${outcome}`).removeClass('hidden');
  }
}(jQuery));
