import './styles/dashboardlayout.css';
import SideBar from "./SideBar";
import BitcoinBlockExplorer from "./BitcoinBlockExplorer";

const Layout = ({ children }) => {


    return (
        <section id="dashboardlayout">
            {children}
            <section id='blockchain_dashboard'>
                <SideBar />
                <BitcoinBlockExplorer />
            </section>
        </section>
    );
};

export default Layout;


/*
    <main id="root">
        <section id="dashboardlayout">
            {children}
        </section>
    </main>
*/



