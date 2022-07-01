
function filter() {
    // Declare variables
    var input, filter, table, tr, td, i, txtValue;
    inputalgo = document.getElementById("filteralgo");
    filteralgo = inputalgo.value.toUpperCase();
    inputframework = document.getElementById("filterframework");
    filterframework = inputframework.value.toUpperCase();
    table = document.getElementById("evaltable");
    tr = table.getElementsByTagName("tr");
    // Loop through all table rows, and hide those who don't match the search query
    for (i = 0; i < tr.length; i++) {
        td1 = tr[i].getElementsByTagName("td")[1];
        td2 = tr[i].getElementsByTagName("td")[0];
        if (td1 && td2) {
            txtValue1 = td1.textContent || td1.innerText;
            txtValue2 = td2.textContent || td2.innerText;
            if (!filteralgo && !filterframework) {
                tr[i].style.display = "";
            }
            else if (filteralgo && filterframework) {
                console.log("in and")
                if (txtValue1.toUpperCase().indexOf(filteralgo) > -1 && txtValue2.toUpperCase().indexOf(filterframework) > -1) {
                    tr[i].style.display = "";
                } else {
                    tr[i].style.display = "none";
                }
            }
            else if (filteralgo) {
                console.log("in algo")
                console.log(txtValue1)
                if (txtValue1.toUpperCase().indexOf(filteralgo) > -1) {
                    tr[i].style.display = "";
                } else {
                    tr[i].style.display = "none";
                }

            }
            else if (filterframework) {
                console.log("in framework")
                console.log(txtValue2)
                if (txtValue2.toUpperCase().indexOf(filterframework) > -1) {
                    tr[i].style.display = "";
                } else {
                    tr[i].style.display = "none";
                }

            }
        }
    }
}