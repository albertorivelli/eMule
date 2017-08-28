using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=234238

namespace eMule
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class KadPage : Page
    {
        private bool m_bConnectRequestDelayedForUPnP;
        private bool m_bKadSuspendDisconnect;
        private bool m_bEd2kSuspendDisconnect;

        public KadPage()
        {
            this.InitializeComponent();
        }

        public void btnConnect_Click(object sender, RoutedEventArgs e)
        {
            if (!((EmuleApp)Windows.UI.Xaml.Application.Current).IsConnected())
		//connect if not currently connected
		if (!((EmuleApp)Windows.UI.Xaml.Application.Current).serverconnect.IsConnecting() && !Kademlia.Kademlia.IsRunning()) {
                StartConnection();
            }
		else {
                CloseConnection();
            }
	else {
                //disconnect if currently connected
                CloseConnection();
            }
        }

        private void StartConnection()
        {
            if ((!((EmuleApp)Windows.UI.Xaml.Application.Current).serverconnect.IsConnecting() && !((EmuleApp)Windows.UI.Xaml.Application.Current).serverconnect.IsConnected())
        || !Kademlia.Kademlia.IsRunning())
	{
                // UPnP is still trying to open the ports. In order to not get a LowID by connecting to the servers / kad before
                // the ports are opened we delay the connection untill UPnP gets a result or the timeout is reached
                // If the user clicks two times on the button, let him have his will and connect regardless
                if (m_hUPnPTimeOutTimer != 0 && !m_bConnectRequestDelayedForUPnP)
                {
                    //AddLogLine(false, GetResString(IDS_DELAYEDBYUPNP));
                    //AddLogLine(true, GetResString(IDS_DELAYEDBYUPNP2));
                    m_bConnectRequestDelayedForUPnP = true;
                    return;
                }
                else
                {
                    m_bConnectRequestDelayedForUPnP = false;
                    if (m_hUPnPTimeOutTimer != 0)
                    {
                        //VERIFY(::KillTimer(NULL, m_hUPnPTimeOutTimer));
                        m_hUPnPTimeOutTimer = 0;
                    }
                    //AddLogLine(true, GetResString(IDS_CONNECTING));

                    // kad
                    if ((thePrefs.GetNetworkKademlia() || m_bKadSuspendDisconnect) && !Kademlia::CKademlia::IsRunning())
                    {
                        Kademlia.Kademlia.Start();
                    }
                }

                //ShowConnectionState();
            }
            m_bEd2kSuspendDisconnect = false;
            m_bKadSuspendDisconnect = false;
        }

        private void CloseConnection()
        {
            if (((EmuleApp)Windows.UI.Xaml.Application.Current).serverconnect.IsConnected()) {
                ((EmuleApp)Windows.UI.Xaml.Application.Current).serverconnect.Disconnect();
            }

            if (((EmuleApp)Windows.UI.Xaml.Application.Current)->serverconnect->IsConnecting()) {
                ((EmuleApp)Windows.UI.Xaml.Application.Current)->serverconnect->StopConnectionTry();
            }
            Kademlia.Kademlia.Stop();
            //theApp.OnlineSig(); // Added By Bouc7 
            //ShowConnectionState();
        }
    }
}
