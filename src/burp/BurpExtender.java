package burp;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JComponent;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.TransferHandler;

public class BurpExtender implements IBurpExtender, IContextMenuFactory {

	private final String EXTENSION_NAME = "Copy Utility";

	private final String COPY_AUTO_DETECT_MENU_TEXT   = "Copy with Charset (auto-detect)";
	private final String COPY_SPECIFIED_MENU_TEXT     = "Copy with Charset";
	private final String COPY_DRAG_AND_DROP_MENU_TEXT = "Copy Item by D&D";
	private final String DEFAULT_CHARSET              = "UTF-8";

	private IExtensionHelpers helpers;
	private IContextMenuInvocation invocation;
	private List<JMenuItem> miCopy;
	private List<JMenuItem> miCopyDD;
	private CopyByCharset cc;
	private boolean isRequest;

	@Override
	/**
	 * IBurpExtenderのメソッド
	 */
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks){
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName(EXTENSION_NAME);
		callbacks.registerContextMenuFactory(this);

		cc = new CopyByCharset();
		miCopy = new ArrayList<JMenuItem>();
		miCopy.add(new JMenuItem(COPY_AUTO_DETECT_MENU_TEXT){{this.addActionListener(cc);}});
		JMenu mCopy = new JMenu(COPY_SPECIFIED_MENU_TEXT);
		String[] encodings = {"UTF-8", "EUC-JP", "Shift_JIS", "ISO-2022-JP"};
		for ( String encoding : encodings ) {
			mCopy.add(new JMenuItem(encoding){{this.addActionListener(cc);}});
		}
		miCopy.add(mCopy);

		miCopyDD = new ArrayList<JMenuItem>();
		miCopyDD.add(new JMenuItem(COPY_DRAG_AND_DROP_MENU_TEXT){{
			this.setTransferHandler(new TransferHandler() {
	            @Override public int getSourceActions(JComponent c) {
	                return MOVE;
	            }
	            @Override protected Transferable createTransferable(JComponent c) {
	                return new TempFileTransferable(invocation);
	            }
			});
			this.addMouseListener(new MouseAdapter() {
	            @Override public void mousePressed(MouseEvent e) {
	                JComponent c = (JComponent) e.getComponent();
	                c.getTransferHandler().exportAsDrag(c, e, TransferHandler.MOVE);
	            }

			});
		}});
	}

	@Override
	public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
		this.invocation = invocation;
		switch ( invocation.getInvocationContext() ) {
		case IContextMenuInvocation.CONTEXT_PROXY_HISTORY:
			return miCopyDD;
		case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
		case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
			this.isRequest = true;
			return this.miCopy;
		case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
		case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
			isRequest = false;
			return miCopy;
		}
		return null;
	}

	private class CopyByCharset implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
			byte[] message;
			if ( isRequest ) {
				message = invocation.getSelectedMessages()[0].getRequest();
			} else {
				message = invocation.getSelectedMessages()[0].getResponse();
			}
			int[] range = invocation.getSelectionBounds();
			byte[] selection = Arrays.copyOfRange(message, range[0], range[1]);

			Charset cs;
			if ( ((JMenuItem)e.getSource()).getText() == COPY_AUTO_DETECT_MENU_TEXT ) {
				cs = Charset.forName(getCharsetName(message));
			} else {
				cs = Charset.forName(((JMenuItem)e.getSource()).getText());
			}

			SetClipboard(new String(selection, cs));
		}
	}

	private void SetClipboard(String str) {
		Toolkit kit = Toolkit.getDefaultToolkit();
		Clipboard clip = kit.getSystemClipboard();
		StringSelection ss = new StringSelection(str);
		clip.setContents(ss, ss);
	}

	private String getCharsetName(byte[] message) {
//		IResponseInfo resInfo = helpers.analyzeResponse(response);

/*
		List<String> headers = resInfo.getHeaders();
		Pattern regex = Pattern.compile("charset=([A-Za-z0-9\\-\\+\\.:_]+)", Pattern.CASE_INSENSITIVE);
		for ( String header : headers ) {
			if ( header.indexOf("Content-Type: ") == 0 && header.indexOf("charset=") > 0 ) {
				Matcher m = regex.matcher(header);
				if ( m.find() ) {
					JOptionPane.showMessageDialog(null, m.group(1));
					return Charset.forName(m.group(1));
				}
			}
		}
*/

		Pattern regex = Pattern.compile("(?:charset|encoding)=[^A-Za-z0-9\\-\\+\\.:_]?([A-Za-z0-9\\-\\+\\.:_]+)", Pattern.CASE_INSENSITIVE);
		Matcher m = regex.matcher(helpers.bytesToString(message));
		if ( m.find() ) {
			return m.group(1);
		}
//		byte[] resBody = Arrays.copyOfRange(response, resInfo.getBodyOffset(), response.length - 1);
/*
		String[] resLines = helpers.bytesToString(response).split("(\r\n|\n|\r)");
		for ( int i = 0; i < resLines.length; ++i ) {
			Matcher m = regex.matcher(resLines[i]);
			if ( m.find() ) {
				JOptionPane.showMessageDialog(null, m.group(1));
				return Charset.forName(m.group(1));
			}
		}
*/

		return DEFAULT_CHARSET;
	}

	class TempFileTransferable implements Transferable {
	    private File file = null;
	    public TempFileTransferable(IContextMenuInvocation invocation) {
            try {
                file = File.createTempFile("burp_request_response_", ".txt");
                file.deleteOnExit();
                FileOutputStream fos = new FileOutputStream(file);
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
    			for ( int i = 0; i < messages.length; ++i ) {
    				fos.write(messages[i].getRequest());
    				fos.write(new String("\r\n======================================================\r\n").getBytes());
    				fos.write(messages[i].getResponse());
    				fos.write(new String("\r\n======================================================\r\n").getBytes());
    			}
	            fos.close();
            } catch (FileNotFoundException e) {
            } catch (IOException ioe) {
            }
	    }
	    @Override public Object getTransferData(DataFlavor flavor) {
	        return Arrays.asList(file);
	    }
	    @Override public DataFlavor[] getTransferDataFlavors() {
	        return new DataFlavor[] {DataFlavor.javaFileListFlavor};
	    }
	    @Override public boolean isDataFlavorSupported(DataFlavor flavor) {
	        return flavor.equals(DataFlavor.javaFileListFlavor);
	    }
	}
}
