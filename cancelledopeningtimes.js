var url = 'https://ehrenamt.im.zam.haus/api/v0-beta/public/cancelledopeningtimes/24';
fetch(url)
    .then(response => response.json())
    .then(termine => {
        const ul = document.getElementById("infeasibleshifts");
        termine.forEach(item => {
          const startDate = new Date(item.real_start);
          const tag = startDate.toLocaleDateString('de-DE', { weekday: 'long', day: 'numeric', month: 'numeric' }); // z.B. Samstag, 21.6.
          const startTime = startDate.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
		  const endTime = new Date(item.real_end).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
          const li = document.createElement('li');
		  li.textContent = `⚠️ ${tag} um ${startTime}-${endTime} Uhr – ${item.title}: `
		  if(item.reason == "shift_cancelled") {
		  	if(item.reason_description) {
		  		li.textContent += "abgesagt: " + item.reason_description + ".";
		  	} else {
				li.textContent += "abgesagt, z.B. wegen Feiertag.";
			}
		  } else if(item.reason == "nobody_in_charge") {
          	li.textContent += "es fehlt (noch) an Ehrenamtlichen.";
          } else {
            li.textContent += "kann voraussichtlich nicht stattfinden.";
          }
          ul.appendChild(li);
        });
    if(termine === undefined || termine.length == 0) {
        const li = document.createElement('li');
        li.textContent = `✅ in den nächsten 24 Stunden können voraussichtlich alle Öffnungszeiten durchgeführt werden. Dank der großartigen Ehrenamtlichen des ZAM ❤️`;
        ul.appendChild(li);
    }
	});
