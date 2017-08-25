/**
 * Created by Brock on 3/13/2017.
 */

// variable to stor my video
var video = videojs('super-video', {
    fluid:true,
    autoplay:true,
    controlBar: {
    volumeMenuButton: {
      inline: false,
      vertical: true
    }
  }
});

function notice(e) {
    location.assign("/")
    var confirmationMessage = 'STOP!'
        + 'If you leave this page YOU WILL NOT BE REFUNDED';

    (e || window.event).returnValue = confirmationMessage; //Gecko + IE
    return confirmationMessage; //Gecko + Webkit, Safari, Chrome etc.

}

window.addEventListener("beforeunload",notice);

video.on('ended', function(){
    window.removeEventListener("beforeunload",notice);
    window.location.replace('/');
});

video.ready(function() {
  this.hotkeys({
      enableNumbers: false,
      enableModifiersForNumbers: false,
      seekStep: false,
  });
});

console.log(video);