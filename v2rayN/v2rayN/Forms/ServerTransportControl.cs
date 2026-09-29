using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using v2rayN.Mode;
using v2rayN.Resx;

namespace v2rayN.Forms
{
    public partial class ServerTransportControl : UserControl
    {
        public bool AllowXtls { get; set; }
        private VmessItem vmessItem;

        // Runtime-created Reality UI controls.
        // They are created here instead of Designer.cs so the original
        // 5.39 TLS/XTLS layout can remain unchanged.
        private Panel panTransportScroll;
        private Label labRealityPublicKey;
        private Label labRealityShortId;
        private Label labRealitySpiderX;
        private Label labRealityMldsa65Verify;
        private Label labTlsPinnedPeerCertSha256;
        private Label labTlsVerifyPeerCertByName;
        private TextBox txtRealityPublicKey;
        private TextBox txtRealityShortId;
        private TextBox txtRealitySpiderX;
        private TextBox txtRealityMldsa65Verify;
        private TextBox txtTlsPinnedPeerCertSha256;
        private TextBox txtTlsVerifyPeerCertByName;
        private Button btnGetTlsCertificate;
        private Label labTlsCertificateStatus;

        // Binding flag prevents the security panel from being repeatedly
        // rearranged while a node is being loaded.
        private bool isBindingServer;

        // Original 5.39 layout values.
        private int originalGbTransportHeight;
        private int originalPanTlsMoreHeight;
        private Rectangle originalLabSniBounds;
        private Rectangle originalTxtSniBounds;
        private Rectangle originalLabFingerprintBounds;
        private Rectangle originalCmbFingerprintBounds;
        private Rectangle originalLabAllowInsecureBounds;
        private Rectangle originalCmbAllowInsecureBounds;
        private Rectangle originalLabel1Bounds;
        private Rectangle originalClbAlpnBounds;

        public ServerTransportControl()
        {
            InitializeComponent();

            InitializeScrollHost();
            CaptureOriginalLayout();
            CreateRealityControls();
            UpdateSecurityPanel();
        }

        private void ServerTransportControl_Load(object sender, EventArgs e)
        {
        }

        private void InitializeScrollHost()
        {
            panTransportScroll = new Panel
            {
                Name = "panTransportScroll",
                Dock = DockStyle.Fill,
                AutoScroll = false,
                BackColor = this.BackColor
            };

            Controls.Remove(gbTransport);

            panTransportScroll.Controls.Add(gbTransport);
            Controls.Add(panTransportScroll);

            panTransportScroll.BringToFront();

            gbTransport.Dock = DockStyle.Fill;
            gbTransport.Location = new Point(0, 0);
            gbTransport.Anchor = AnchorStyles.Top | AnchorStyles.Left;

            panTransportScroll.Resize += panTransportScroll_Resize;
        }

        private void CaptureOriginalLayout()
        {
            originalGbTransportHeight = gbTransport.Height;
            originalPanTlsMoreHeight = panTlsMore.Height;

            originalLabSniBounds = labSNI.Bounds;
            originalTxtSniBounds = txtSNI.Bounds;
            originalLabFingerprintBounds = labfingerprint.Bounds;
            originalCmbFingerprintBounds = cmbFingerprint.Bounds;
            originalLabAllowInsecureBounds = labAllowInsecure.Bounds;
            originalCmbAllowInsecureBounds = cmbAllowInsecure.Bounds;
            originalLabel1Bounds = label1.Bounds;
            originalClbAlpnBounds = clbAlpn.Bounds;
        }

        private void CreateRealityControls()
        {
            labRealityPublicKey = CreateRealityLabel(
                "PublicKey/Password",
                "labRealityPublicKey");

            labRealityShortId = CreateRealityLabel(
                "ShortId",
                "labRealityShortId");

            labRealitySpiderX = CreateRealityLabel(
                "SpiderX",
                "labRealitySpiderX");

            labRealityMldsa65Verify = CreateRealityLabel(
                "mldsa65Verify",
                "labRealityMldsa65Verify");

            labTlsPinnedPeerCertSha256 = CreateRealityLabel(
                "PCS / Cert SHA256",
                "labTlsPinnedPeerCertSha256");

            labTlsVerifyPeerCertByName = CreateRealityLabel(
                "VCN / Cert Name",
                "labTlsVerifyPeerCertByName");  

            txtRealityPublicKey = CreateRealityTextBox(
                "txtRealityPublicKey");

            txtRealityShortId = CreateRealityTextBox(
                "txtRealityShortId");

            txtRealitySpiderX = CreateRealityTextBox(
                "txtRealitySpiderX");

            txtRealityMldsa65Verify = CreateRealityTextBox(
                "txtRealityMldsa65Verify");

            txtRealityShortId.Width = 189;

            txtRealityPublicKey.TabIndex = 50;
            txtRealityShortId.TabIndex = 51;
            txtRealitySpiderX.TabIndex = 52;
            txtRealityMldsa65Verify.TabIndex = 53;

            labRealityPublicKey.Visible = false;
            labRealityShortId.Visible = false;
            labRealitySpiderX.Visible = false;
            labRealityMldsa65Verify.Visible = false;

            txtRealityPublicKey.Visible = false;
            txtRealityShortId.Visible = false;
            txtRealitySpiderX.Visible = false;
            txtRealityMldsa65Verify.Visible = false;

            txtTlsPinnedPeerCertSha256 = CreateRealityTextBox(
                "txtTlsPinnedPeerCertSha256");

            txtTlsVerifyPeerCertByName = CreateRealityTextBox(
                "txtTlsVerifyPeerCertByName");

            // All runtime controls must belong to panTlsMore, otherwise
            // they can have correct coordinates but will not be rendered.
            panTlsMore.Controls.Add(labRealityPublicKey);
            panTlsMore.Controls.Add(txtRealityPublicKey);
            panTlsMore.Controls.Add(labRealityShortId);
            panTlsMore.Controls.Add(txtRealityShortId);
            panTlsMore.Controls.Add(labRealitySpiderX);
            panTlsMore.Controls.Add(txtRealitySpiderX);
            panTlsMore.Controls.Add(labRealityMldsa65Verify);
            panTlsMore.Controls.Add(txtRealityMldsa65Verify);
            panTlsMore.Controls.Add(labTlsPinnedPeerCertSha256);
            panTlsMore.Controls.Add(txtTlsPinnedPeerCertSha256);
            panTlsMore.Controls.Add(labTlsVerifyPeerCertByName);
            panTlsMore.Controls.Add(txtTlsVerifyPeerCertByName);

            btnGetTlsCertificate = new Button
            {
                Name = "btnGetTlsCertificate",
                Text = "自动获取证书信息",
                AutoSize = false,
                Width = 130,
                Height = 25,
                TabIndex = 54
            };
            btnGetTlsCertificate.Click += btnGetTlsCertificate_Click;

            labTlsCertificateStatus = new Label
            {
                Name = "labTlsCertificateStatus",
                Text = "状态：尚未获取",
                AutoSize = true,
                Font = labSNI.Font,
                Margin = labSNI.Margin
            };

            panTlsMore.Controls.Add(btnGetTlsCertificate);
            panTlsMore.Controls.Add(labTlsCertificateStatus);
        }

        private void btnGetTlsCertificate_Click(object sender, EventArgs e)
        {
            // UI placeholder only. The actual TLS certificate retrieval
            // will be implemented in the next stage.
            labTlsCertificateStatus.Text = "状态：获取功能尚未接入";
        }

        private Label CreateRealityLabel(string text, string name)
        {
            Label label = new Label
            {
                Name = name,
                Text = text,
                AutoSize = true,
                Font = labSNI.Font,
                Margin = labSNI.Margin
            };

            return label;
        }

        private TextBox CreateRealityTextBox(string name)
        {
            TextBox textBox = new TextBox
            {
                Name = name,
                Font = txtSNI.Font,
                BorderStyle = txtSNI.BorderStyle,
                Height = txtSNI.Height,
                Margin = txtSNI.Margin,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };

            return textBox;
        }

        private void Init(VmessItem item)
        {
            vmessItem = item;

            // Prevent duplicate entries when the same control is reused.
            cmbNetwork.Items.Clear();
            cmbFingerprint.Items.Clear();
            cmbStreamSecurity.Items.Clear();

            cmbNetwork.Items.AddRange(Global.networks.ToArray());

            cmbStreamSecurity.Items.Add(string.Empty);
            cmbStreamSecurity.Items.Add(Global.StreamSecurity);

            if (AllowXtls)
            {
                cmbStreamSecurity.Items.Add(Global.StreamSecurityX);
            }

            cmbStreamSecurity.Items.Add(Global.StreamSecurityReality);

            cmbFingerprint.Items.AddRange(Global.fingerprints.ToArray());
        }

        public void BindingServer(VmessItem item)
        {
            isBindingServer = true;

            try
            {
                Init(item);

                cmbNetwork.Text = vmessItem.network;
                cmbHeaderType.Text = vmessItem.headerType;
                txtRequestHost.Text = vmessItem.requestHost;
                txtPath.Text = vmessItem.path;
                cmbStreamSecurity.Text = vmessItem.streamSecurity;
                cmbAllowInsecure.Text = vmessItem.allowInsecure;
                txtSNI.Text = vmessItem.sni;
                cmbFingerprint.Text = vmessItem.fingerprint;

                // Clear previous ALPN selections first.
                for (int i = 0; i < clbAlpn.Items.Count; i++)
                {
                    clbAlpn.SetItemChecked(i, false);
                }

                if (vmessItem.alpn != null)
                {
                    for (int i = 0; i < clbAlpn.Items.Count; i++)
                    {
                        if (vmessItem.alpn.Contains(clbAlpn.Items[i].ToString()))
                        {
                            clbAlpn.SetItemChecked(i, true);
                        }
                    }
                }

                // Reality fields are shown in a single UI textbox.
                // Prefer the modern "password" field when available,
                // but fall back to the legacy "publicKey" field.
                if (!string.IsNullOrWhiteSpace(vmessItem.password))
                {
                    txtRealityPublicKey.Text = vmessItem.password;
                }
                else
                {
                    txtRealityPublicKey.Text = vmessItem.publicKey;
                }

                txtRealityShortId.Text = vmessItem.shortId;
                txtRealitySpiderX.Text = vmessItem.spiderX;
                txtRealityMldsa65Verify.Text = vmessItem.mldsa65Verify;
                txtTlsPinnedPeerCertSha256.Text = vmessItem.pinnedPeerCertSha256 ?? "";
                txtTlsVerifyPeerCertByName.Text = vmessItem.verifyPeerCertByName ?? "";
                labTlsCertificateStatus.Text = "状态：尚未获取";
            }
            finally
            {
                isBindingServer = false;
                UpdateSecurityPanel();
            }
        }

        public void ClearServer(VmessItem item)
        {
            isBindingServer = true;

            try
            {
                Init(item);

                cmbNetwork.Text = Global.DefaultNetwork;
                cmbHeaderType.Text = Global.None;
                txtRequestHost.Text = "";
                cmbStreamSecurity.Text = "";
                cmbAllowInsecure.Text = "";
                txtPath.Text = "";
                txtSNI.Text = "";
                cmbFingerprint.Text = "";

                txtRealityPublicKey.Text = "";
                txtRealityShortId.Text = "";
                txtRealitySpiderX.Text = "";
                txtRealityMldsa65Verify.Text = "";
                txtTlsPinnedPeerCertSha256.Text = "";
                txtTlsVerifyPeerCertByName.Text = "";
                labTlsCertificateStatus.Text = "状态：尚未获取";

                for (int i = 0; i < clbAlpn.Items.Count; i++)
                {
                    clbAlpn.SetItemChecked(i, false);
                }
            }
            finally
            {
                isBindingServer = false;
                UpdateSecurityPanel();
            }
        }

        public void EndBindingServer()
        {
            string network = cmbNetwork.Text;
            string headerType = cmbHeaderType.Text;
            string requestHost = txtRequestHost.Text;
            string path = txtPath.Text;
            string streamSecurity = cmbStreamSecurity.Text;
            string allowInsecure = cmbAllowInsecure.Text;
            string sni = txtSNI.Text;
            string fingerprint = cmbFingerprint.Text;

            vmessItem.network = network;
            vmessItem.headerType = headerType;
            vmessItem.requestHost = requestHost.Replace(" ", "");
            vmessItem.path = path.Replace(" ", "");
            vmessItem.streamSecurity = streamSecurity;
            vmessItem.allowInsecure = allowInsecure;
            vmessItem.sni = sni;
            vmessItem.fingerprint = fingerprint;

            var alpn = new List<string>();

            for (int i = 0; i < clbAlpn.Items.Count; i++)
            {
                if (clbAlpn.GetItemChecked(i))
                {
                    alpn.Add(clbAlpn.Items[i].ToString());
                }
            }

            vmessItem.alpn = alpn;

            // Save Reality fields only when the node is currently Reality.
            // For TLS/XTLS nodes the previous Reality values are preserved.
            if (streamSecurity == Global.StreamSecurityReality)
            {
                string realityPassword = txtRealityPublicKey.Text.Trim();

                vmessItem.publicKey = realityPassword;
                vmessItem.password = realityPassword;
                vmessItem.shortId = txtRealityShortId.Text.Trim();
                vmessItem.spiderX = txtRealitySpiderX.Text.Trim();
                vmessItem.mldsa65Verify = txtRealityMldsa65Verify.Text.Trim();
            }

            // PCS / VCN belong to the TLS certificate verification settings.
            // Save them independently of the currently selected security mode.
            vmessItem.pinnedPeerCertSha256 = txtTlsPinnedPeerCertSha256.Text.Trim();
            vmessItem.verifyPeerCertByName = txtTlsVerifyPeerCertByName.Text.Trim();
        }

        private void cmbNetwork_SelectedIndexChanged(object sender, EventArgs e)
        {
            SetHeaderType();
            SetTips();
        }

        private void SetHeaderType()
        {
            cmbHeaderType.Items.Clear();

            string network = cmbNetwork.Text;

            if (Utils.IsNullOrEmpty(network))
            {
                cmbHeaderType.Items.Add(Global.None);
                return;
            }

            if (network.Equals(Global.DefaultNetwork))
            {
                cmbHeaderType.Items.Add(Global.None);
                cmbHeaderType.Items.Add(Global.TcpHeaderHttp);
            }
            else if (network.Equals("kcp") || network.Equals("quic"))
            {
                cmbHeaderType.Items.Add(Global.None);
                cmbHeaderType.Items.AddRange(Global.kcpHeaderTypes.ToArray());
            }
            else if (network.Equals("grpc"))
            {
                cmbHeaderType.Items.Add(Global.GrpcgunMode);
                cmbHeaderType.Items.Add(Global.GrpcmultiMode);
            }
            else
            {
                cmbHeaderType.Items.Add(Global.None);
            }

            cmbHeaderType.SelectedIndex = 0;
        }

        private void SetTips()
        {
            string network = cmbNetwork.Text;

            if (Utils.IsNullOrEmpty(network))
            {
                network = Global.DefaultNetwork;
            }

            labHeaderType.Visible = true;

            tipRequestHost.Text =
            tipPath.Text =
            tipHeaderType.Text = string.Empty;

            if (network.Equals(Global.DefaultNetwork))
            {
                tipRequestHost.Text = ResUI.TransportRequestHostTip1;
                tipHeaderType.Text = ResUI.TransportHeaderTypeTip1;
            }
            else if (network.Equals("kcp"))
            {
                tipHeaderType.Text = ResUI.TransportHeaderTypeTip2;
                tipPath.Text = ResUI.TransportPathTip5;
            }
            else if (network.Equals("ws"))
            {
                tipRequestHost.Text = ResUI.TransportRequestHostTip2;
                tipPath.Text = ResUI.TransportPathTip1;
            }
            else if (network.Equals("h2"))
            {
                tipRequestHost.Text = ResUI.TransportRequestHostTip3;
                tipPath.Text = ResUI.TransportPathTip2;
            }
            else if (network.Equals("quic"))
            {
                tipRequestHost.Text = ResUI.TransportRequestHostTip4;
                tipPath.Text = ResUI.TransportPathTip3;
                tipHeaderType.Text = ResUI.TransportHeaderTypeTip3;
            }
            else if (network.Equals("grpc"))
            {
                tipPath.Text = ResUI.TransportPathTip4;
                tipHeaderType.Text = ResUI.TransportHeaderTypeTip4;
                labHeaderType.Visible = false;
            }
        }

        private void cmbStreamSecurity_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (isBindingServer)
            {
                return;
            }

            UpdateSecurityPanel();
        }

        private void UpdateSecurityPanel()
        {
            string security = cmbStreamSecurity.Text;

            if (Utils.IsNullOrEmpty(security))
            {
                RestoreOriginalSecurityLayout();
                panTlsMore.Hide();

                panTransportScroll.AutoScroll = false;
                panTransportScroll.AutoScrollMinSize = new Size(0, 0);
                return;
            }

            if (security == Global.StreamSecurityReality)
            {
                ApplyRealityLayout();
            }
            else if (security == Global.StreamSecurity)
            {
                ApplyTlsPinningLayout();
            }
            else
            {
                RestoreOriginalSecurityLayout();
                panTlsMore.Show();

                panTransportScroll.AutoScroll = false;
                panTransportScroll.AutoScrollMinSize = new Size(0, 0);
            }
        }

        private void ApplyRealityLayout()
        {
            labTlsPinnedPeerCertSha256.Visible = false;
            txtTlsPinnedPeerCertSha256.Visible = false;
            labTlsVerifyPeerCertByName.Visible = false;
            txtTlsVerifyPeerCertByName.Visible = false;
            btnGetTlsCertificate.Visible = false;
            labTlsCertificateStatus.Visible = false;

            panTlsMore.SuspendLayout();

            panTlsMore.Show();

            // Hide TLS-only controls.
            labAllowInsecure.Hide();
            cmbAllowInsecure.Hide();
            label1.Hide();
            clbAlpn.Hide();

            // Keep SNI and fingerprint in the familiar 5.39 positions,
            // but rearrange them into a compact vertical Reality layout.
            labSNI.Show();
            txtSNI.Show();
            labfingerprint.Show();
            cmbFingerprint.Show();

            gbTransport.Dock = DockStyle.None;
            gbTransport.Location = new Point(0, 0);

            int availableWidth = panTransportScroll.ClientSize.Width
                - SystemInformation.VerticalScrollBarWidth
                - 4;

            if (availableWidth < 300)
            {
                availableWidth = 300;
            }

            gbTransport.Width = availableWidth;

            int realityPanelWidth = gbTransport.ClientSize.Width
                - panTlsMore.Left
                - 8;

            if (realityPanelWidth < 300)
            {
                realityPanelWidth = 300;
            }

            panTlsMore.Width = realityPanelWidth;
            panTlsMore.Height = 220;

            const int labelLeft = 16;
            const int controlLeft = 133;
            const int controlRight = 8;

            labSNI.Location = new Point(labelLeft, 12);
            txtSNI.Location = new Point(controlLeft, 9);
            txtSNI.Width = Math.Max(
                200,
                panTlsMore.ClientSize.Width - txtSNI.Left - controlRight);

            labfingerprint.Location = new Point(labelLeft, 47);

            cmbFingerprint.Location = new Point(controlLeft, 44);
            cmbFingerprint.Width = Math.Max(
                120,
                Math.Min(
                    originalCmbFingerprintBounds.Width,
                    panTlsMore.ClientSize.Width
                        - cmbFingerprint.Left
                        - controlRight));

            labRealityPublicKey.Location = new Point(labelLeft, 82);
            txtRealityPublicKey.Location = new Point(controlLeft, 79);
            txtRealityPublicKey.Width = Math.Max(
                200,
                panTlsMore.ClientSize.Width
                    - txtRealityPublicKey.Left
                    - controlRight);

            labRealityShortId.Location = new Point(labelLeft, 117);
            txtRealityShortId.Location = new Point(controlLeft, 114);
            txtRealityShortId.Width = 189;

            labRealitySpiderX.Location = new Point(labelLeft, 152);
            txtRealitySpiderX.Location = new Point(controlLeft, 149);
            txtRealitySpiderX.Width = Math.Max(
                200,
                panTlsMore.ClientSize.Width
                    - txtRealitySpiderX.Left
                    - controlRight);

            labRealityMldsa65Verify.Location = new Point(labelLeft, 187);
            txtRealityMldsa65Verify.Location = new Point(controlLeft, 184);
            txtRealityMldsa65Verify.Width = Math.Max(
                200,
                panTlsMore.ClientSize.Width
                    - txtRealityMldsa65Verify.Left
                    - controlRight);

            labRealityPublicKey.Show();
            labRealityShortId.Show();
            labRealitySpiderX.Show();
            labRealityMldsa65Verify.Show();

            txtRealityPublicKey.Show();
            txtRealityShortId.Show();
            txtRealitySpiderX.Show();
            txtRealityMldsa65Verify.Show();

            panTlsMore.ResumeLayout();

            gbTransport.Height = Math.Max(
                originalGbTransportHeight,
                panTlsMore.Bottom + 8);

            panTransportScroll.AutoScroll = true;
            panTransportScroll.AutoScrollMinSize =
                new Size(gbTransport.Right + 1, gbTransport.Bottom + 1);
        }

        private void ApplyTlsPinningLayout()
        {
            panTlsMore.SuspendLayout();

            // TLS must always start from the original 5.39 layout.
            // This prevents the previous Reality positions from leaking into TLS.
            labSNI.Bounds = originalLabSniBounds;
            txtSNI.Bounds = originalTxtSniBounds;
            labfingerprint.Bounds = originalLabFingerprintBounds;
            cmbFingerprint.Bounds = originalCmbFingerprintBounds;
            labAllowInsecure.Bounds = originalLabAllowInsecureBounds;
            cmbAllowInsecure.Bounds = originalCmbAllowInsecureBounds;
            label1.Bounds = originalLabel1Bounds;
            clbAlpn.Bounds = originalClbAlpnBounds;

            labSNI.Show();
            txtSNI.Show();
            labfingerprint.Show();
            cmbFingerprint.Show();
            labAllowInsecure.Show();
            cmbAllowInsecure.Show();
            label1.Show();
            clbAlpn.Show();

            // Hide all Reality-only controls.
            labRealityPublicKey.Hide();
            labRealityShortId.Hide();
            labRealitySpiderX.Hide();
            labRealityMldsa65Verify.Hide();
            txtRealityPublicKey.Hide();
            txtRealityShortId.Hide();
            txtRealitySpiderX.Hide();
            txtRealityMldsa65Verify.Hide();

            // Show TLS certificate verification controls.
            labTlsPinnedPeerCertSha256.Show();
            txtTlsPinnedPeerCertSha256.Show();
            labTlsVerifyPeerCertByName.Show();
            txtTlsVerifyPeerCertByName.Show();
            btnGetTlsCertificate.Show();
            labTlsCertificateStatus.Show();

            // Put the certificate button on its own row directly below Fingerprint.
            // Keep it aligned with the main input controls. The status label
            // sits to its right and remains inside the scrollable panel.
            btnGetTlsCertificate.Location = new Point(172, 100);
            labTlsCertificateStatus.Location = new Point(310, 105);

            // The original panTlsMore is 131px high.
            // Its last original control (ALPN) ends around y=33.
            // Put PCS/VCN clearly below the original TLS controls instead
            // of guessing from the current/previous layout.
            const int labelLeft = 16;
            const int controlLeft = 172;
            const int row1Top = 150;
            const int row2Top = 185;

            labTlsPinnedPeerCertSha256.Location = new Point(labelLeft, row1Top);
            txtTlsPinnedPeerCertSha256.Location = new Point(controlLeft, row1Top - 4);
            txtTlsPinnedPeerCertSha256.Width = Math.Max(250, panTlsMore.ClientSize.Width - controlLeft - 8);

            labTlsVerifyPeerCertByName.Location = new Point(labelLeft, row2Top);
            txtTlsVerifyPeerCertByName.Location = new Point(controlLeft, row2Top - 4);
            txtTlsVerifyPeerCertByName.Width = Math.Max(250, panTlsMore.ClientSize.Width - controlLeft - 8);

            // Make enough room for both new rows.
            panTlsMore.Height = row2Top + Math.Max(25, txtTlsVerifyPeerCertByName.Height) + 8;
            panTlsMore.Show();

            panTlsMore.ResumeLayout();

            // The outer scroll host must know the enlarged content height.
            gbTransport.Dock = DockStyle.None;
            gbTransport.Location = new Point(0, 0);
            gbTransport.Width = Math.Max(300, panTransportScroll.ClientSize.Width - SystemInformation.VerticalScrollBarWidth - 4);
            gbTransport.Height = Math.Max(originalGbTransportHeight, panTlsMore.Bottom + 8);

            panTransportScroll.AutoScroll = true;
            panTransportScroll.AutoScrollMinSize =
                new Size(gbTransport.Right + 1, gbTransport.Bottom + 1);
        }

        private void RestoreOriginalSecurityLayout()
        {
            labTlsPinnedPeerCertSha256.Visible = false;
            txtTlsPinnedPeerCertSha256.Visible = false;
            labTlsVerifyPeerCertByName.Visible = false;
            txtTlsVerifyPeerCertByName.Visible = false;
            btnGetTlsCertificate.Visible = false;
            labTlsCertificateStatus.Visible = false;
            panTlsMore.SuspendLayout();

            panTlsMore.Height = originalPanTlsMoreHeight;

            labSNI.Bounds = originalLabSniBounds;
            txtSNI.Bounds = originalTxtSniBounds;
            labfingerprint.Bounds = originalLabFingerprintBounds;
            cmbFingerprint.Bounds = originalCmbFingerprintBounds;
            labAllowInsecure.Bounds = originalLabAllowInsecureBounds;
            cmbAllowInsecure.Bounds = originalCmbAllowInsecureBounds;
            label1.Bounds = originalLabel1Bounds;
            clbAlpn.Bounds = originalClbAlpnBounds;

            labAllowInsecure.Show();
            cmbAllowInsecure.Show();
            label1.Show();
            clbAlpn.Show();

            labRealityPublicKey.Hide();
            labRealityShortId.Hide();
            labRealitySpiderX.Hide();
            labRealityMldsa65Verify.Hide();

            txtRealityPublicKey.Hide();
            txtRealityShortId.Hide();
            txtRealitySpiderX.Hide();
            txtRealityMldsa65Verify.Hide();

            panTlsMore.ResumeLayout();

            gbTransport.Dock = DockStyle.Fill;
            gbTransport.Location = new Point(0, 0);
            gbTransport.Height = originalGbTransportHeight;
        }

        private void panTransportScroll_Resize(object sender, EventArgs e)
        {
            if (isBindingServer)
            {
                return;
            }

            if (cmbStreamSecurity.Text == Global.StreamSecurityReality)
            {
                ApplyRealityLayout();
            }
            else if (cmbStreamSecurity.Text == Global.StreamSecurity)
            {
                ApplyTlsPinningLayout();
            }
        }
    }
}